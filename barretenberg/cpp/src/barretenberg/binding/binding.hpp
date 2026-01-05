#if !defined(_BINDING_HPP)
#define _BINDING_HPP

#include <cstdint>

#if defined(__cplusplus)
extern "C" {
#endif // __cplusplus

int gen_crs_global();

int gen_vk(const uint8_t* bytecode, uint64_t bytecode_len, uint8_t* vk, uint64_t* vk_len);

int prove(const uint8_t* bytecode,
          uint64_t bytecode_len,
          const uint8_t* witness,
          uint64_t witness_len,
          const uint8_t* vk,
          uint64_t vk_len,
          uint8_t* proof,
          uint64_t* proof_len,
          uint8_t* publics,
          uint64_t* publics_len);

int verify(const uint8_t* vk,
           uint64_t vk_len,
           const uint8_t* proof,
           uint64_t proof_len,
           const uint8_t* publics,
           uint64_t publics_len,
           int* response);

#if defined(__cplusplus)
}
#endif // __cplusplus

#endif // _BINDING_HPP
