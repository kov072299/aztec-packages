#include "barretenberg/api/file_io.hpp"
#include "barretenberg/bbapi/bbapi_ultra_honk.hpp"
#include "barretenberg/common/bb_bench.hpp"
#include "barretenberg/common/get_bytecode.hpp"
#include "barretenberg/common/map.hpp"
#include "barretenberg/common/serialize.hpp"
#include "barretenberg/common/throw_or_abort.hpp"
#include "barretenberg/dsl/acir_format/acir_to_constraint_buf.hpp"
#include "barretenberg/dsl/acir_format/proof_surgeon.hpp"
#include "barretenberg/dsl/acir_proofs/honk_contract.hpp"
#include "barretenberg/dsl/acir_proofs/honk_optimized_contract.hpp"
#include "barretenberg/dsl/acir_proofs/honk_zk_contract.hpp"
#include "barretenberg/honk/proof_system/types/proof.hpp"
#include "barretenberg/numeric/uint256/uint256.hpp"
#include "barretenberg/special_public_inputs/special_public_inputs.hpp"
#include "barretenberg/srs/factories/native_crs_factory.hpp"
#include "barretenberg/srs/global_crs.hpp"
#include <cstring>
#include <iomanip>
#include <libdeflate.h>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <vector>

#include "binding.hpp"

std::vector<uint8_t> bnd_get_bytecode(const uint8_t* bytecode, uint64_t bytecode_len)
{
    std::string json_str(reinterpret_cast<const char*>(bytecode), bytecode_len);

    nlohmann::json json_data = nlohmann::json::parse(json_str);
    std::string base64_bytecode = json_data["bytecode"];

    return decode_bytecode(base64_bytecode);
}

namespace {
std::vector<uint8_t> gzip_decompress2([[maybe_unused]] const std::vector<uint8_t>& compressed)
{
    std::vector<uint8_t> decompressed;
    decompressed.resize(1024ULL * 128ULL); // Initial size guess

    for (;;) {
        auto decompressor = std::unique_ptr<libdeflate_decompressor, void (*)(libdeflate_decompressor*)>{
            libdeflate_alloc_decompressor(), libdeflate_free_decompressor
        };
        size_t actual_size = 0;
        libdeflate_result result = libdeflate_gzip_decompress(decompressor.get(),
                                                              compressed.data(),
                                                              compressed.size(),
                                                              decompressed.data(),
                                                              decompressed.size(),
                                                              &actual_size);

        if (result == LIBDEFLATE_INSUFFICIENT_SPACE) {
            decompressed.resize(decompressed.size() * 2);
            continue;
        }
        if (result == LIBDEFLATE_BAD_DATA) {
            throw std::runtime_error("Invalid gzip data");
        }
        decompressed.resize(actual_size);
        break;
    }
    return decompressed;
}
} // namespace

std::vector<uint8_t> bnd_get_witness(const uint8_t* wit, uint64_t wit_len)
{
    std::vector<uint8_t> compressed(wit, wit + wit_len);
    return gzip_decompress2(compressed);
}

int bnd_dcopy(std::vector<uint8_t> const& v, uint8_t* buf, uint64_t* buf_len)
{
    if (*buf_len < v.size()) {
        return -1;
    }

    std::memcpy(buf, v.data(), v.size());
    *buf_len = v.size();

    return 0;
}

int gen_crs_global()
{
    bb::srs::init_net_crs_factory(bb::srs::bb_crs_path());
    return 0;
}

int gen_vk(const uint8_t* bytecode, uint64_t bytecode_len, uint8_t* vk, uint64_t* vk_len)
{
    auto bc = bnd_get_bytecode(bytecode, bytecode_len);

    // Convert flags to ProofSystemSettings
    bb::bbapi::ProofSystemSettings settings{ .ipa_accumulation = false,
                                             .oracle_hash_type = std::string("poseidon2"),
                                             .disable_zk = false };

    auto response =
        bb::bbapi::CircuitComputeVk{ .circuit = { .name = "circuit", .bytecode = std::move(bc) }, .settings = settings }
            .execute();
    if (bnd_dcopy(response.bytes, vk, vk_len)) {
        return -1;
    }

    return 0;
}

int prove(const uint8_t* bytecode,
          uint64_t bytecode_len,
          const uint8_t* witness,
          uint64_t witness_len,
          const uint8_t* vk,
          uint64_t vk_len,
          uint8_t* proof,
          uint64_t* proof_len,
          uint8_t* publics,
          uint64_t* publics_len)
{
    auto bc = bnd_get_bytecode(bytecode, bytecode_len);
    auto wt = bnd_get_witness(witness, witness_len);

    // Convert flags to ProofSystemSettings
    bb::bbapi::ProofSystemSettings settings{ .ipa_accumulation = false,
                                             .oracle_hash_type = std::string("poseidon2"),
                                             .disable_zk = false };
    std::vector<uint8_t> vk_bytes(vk, vk + vk_len);

    auto response = bb::bbapi::CircuitProve{ .circuit = { .name = "circuit",
                                                          .bytecode = std::move(bc),
                                                          .verification_key = std::move(vk_bytes) },
                                             .witness = std::move(wt),
                                             .settings = std::move(settings) }
                        .execute();
    auto pubin_buf = to_buffer(response.public_inputs);
    auto proof_buf = to_buffer(response.proof);

    if (bnd_dcopy(pubin_buf, publics, publics_len)) {
        return -1;
    }

    if (bnd_dcopy(proof_buf, proof, proof_len)) {
        return -2;
    }

    return 0;
}

int verify(const uint8_t* vk,
           uint64_t vk_len,
           const uint8_t* proof,
           uint64_t proof_len,
           const uint8_t* publics,
           uint64_t publics_len,
           int* response)
{
    auto public_inputs = many_from_buffer<bb::numeric::uint256_t>(std::vector<uint8_t>(publics, publics + publics_len));
    auto proof_data = many_from_buffer<bb::numeric::uint256_t>(std::vector<uint8_t>(proof, proof + proof_len));
    std::vector<uint8_t> vk_data(vk, vk + vk_len);

    bb::bbapi::ProofSystemSettings settings{ .ipa_accumulation = false,
                                             .oracle_hash_type = std::string("poseidon2"),
                                             .disable_zk = false };
    auto resp = bb::bbapi::CircuitVerify{ .verification_key = std::move(vk_data),
                                          .public_inputs = std::move(public_inputs),
                                          .proof = std::move(proof_data),
                                          .settings = settings }
                    .execute();
    *response = resp.verified ? 1 : 0;

    return 0;
}
