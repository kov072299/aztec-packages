barretenberg_module(binding chonk bbapi dsl srs libdeflate::libdeflate_static nlohmann_json::nlohmann_json)

#set_property(TARGET libdeflate::libdeflate_static PROPERTY POSITION_INDEPENDENT_CODE ON)

if (NOT WASM)
    add_library(binding_shared SHARED  $<TARGET_OBJECTS:binding_objects>)
    target_link_libraries(binding_shared PRIVATE chonk bbapi dsl srs libdeflate::libdeflate_static nlohmann_json::nlohmann_json)
    target_include_directories(binding_shared PRIVATE binding.hpp)
endif ()

# Link avm_transpiler when library is provided
if(AVM_TRANSPILER_LIB)
    target_link_libraries(api_objects PRIVATE avm_transpiler)
endif()
