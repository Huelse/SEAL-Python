#include <pybind11/pybind11.h>
#include <pybind11/stl_bind.h>
#include <pybind11/numpy.h>
#include <pybind11/stl.h>
#include "seal/seal.h"
#include <fstream>

using namespace seal;
namespace py = pybind11;

#define SEAL_DOC(text) text

PYBIND11_MAKE_OPAQUE(std::vector<double>);
PYBIND11_MAKE_OPAQUE(std::vector<std::complex<double>>);
PYBIND11_MAKE_OPAQUE(std::vector<std::uint64_t>);
PYBIND11_MAKE_OPAQUE(std::vector<std::int64_t>);

PYBIND11_MODULE(seal, m)
{
    m.doc() = "Microsoft SEAL for Python, from https://github.com/Huelse/SEAL-Python";
    m.attr("__version__")  = "4.1.2";

    py::bind_vector<std::vector<double>>(
        m, "VectorDouble", py::buffer_protocol(),
        SEAL_DOC("Vector container for double values used by SEAL encoders."));
    py::bind_vector<std::vector<std::complex<double>>>(
        m, "VectorComplex", py::buffer_protocol(),
        SEAL_DOC("Vector container for complex<double> values used by CKKS."));
    py::bind_vector<std::vector<std::uint64_t>>(
        m, "VectorUInt", py::buffer_protocol(),
        SEAL_DOC("Vector container for unsigned 64-bit integer slots."));
    py::bind_vector<std::vector<std::int64_t>>(
        m, "VectorInt", py::buffer_protocol(),
        SEAL_DOC("Vector container for signed 64-bit integer slots."));

    // encryptionparams.h
    py::enum_<scheme_type>(m, "scheme_type", SEAL_DOC("Describes the homomorphic encryption scheme to use."))
        .value("none", scheme_type::none)
        .value("bfv", scheme_type::bfv)
        .value("ckks", scheme_type::ckks)
        .value("bgv", scheme_type::bgv);

    // serialization.h
    py::enum_<compr_mode_type>(m, "compr_mode_type", SEAL_DOC("Compression mode used when serializing SEAL objects."))
        .value("none", compr_mode_type::none)
#ifdef SEAL_USE_ZLIB
        .value("zlib", compr_mode_type::zlib)
#endif
#ifdef SEAL_USE_ZSTD
        .value("zstd", compr_mode_type::zstd)
#endif
        ;

    // memorymanager.h
    py::class_<MemoryPoolHandle>(
        m, "MemoryPoolHandle",
        SEAL_DOC("Handle to a memory pool used by SEAL for efficient temporary allocations."))
        .def(py::init<>(), SEAL_DOC("Construct an uninitialized memory pool handle."))
        .def_static("Global", &MemoryPoolHandle::Global, SEAL_DOC("Return a handle to the global memory pool."))
#ifndef _M_CEE
        .def_static("ThreadLocal", &MemoryPoolHandle::ThreadLocal, SEAL_DOC("Return a handle to the thread-local memory pool."))
#endif
        .def_static(
            "New", &MemoryPoolHandle::New, py::arg("clear_on_destruction") = false,
            SEAL_DOC("Create a new independent memory pool."))
        .def("pool_count", &MemoryPoolHandle::pool_count, SEAL_DOC("Return the number of memory pools referenced by this handle."))
        .def("alloc_byte_count", &MemoryPoolHandle::alloc_byte_count, SEAL_DOC("Return the number of bytes allocated by the pool."))
        .def("use_count", &MemoryPoolHandle::use_count, SEAL_DOC("Return the reference count of the underlying pool."))
        .def("is_initialized", [](const MemoryPoolHandle &pool){
            return static_cast<bool>(pool);
        }, SEAL_DOC("Return True if this handle points to an initialized memory pool."));

    py::class_<MemoryManager>(m, "MemoryManager", SEAL_DOC("Factory for retrieving SEAL memory pools."))
        .def_static("GetPool", [](){
            return MemoryManager::GetPool();
        }, SEAL_DOC("Return the default memory pool handle."));

    // encryptionparams.h
    py::class_<EncryptionParameters>(
        m, "EncryptionParameters",
        SEAL_DOC("Represents user-configurable encryption settings such as polynomial modulus, coefficient modulus, and plaintext modulus."))
        .def(py::init<scheme_type>(), py::arg("scheme"),
            SEAL_DOC("Create an empty set of encryption parameters for the given scheme."))
        .def(py::init<EncryptionParameters>(), py::arg("copy"),
            SEAL_DOC("Create a copy of an existing EncryptionParameters object."))
        .def("set_poly_modulus_degree", &EncryptionParameters::set_poly_modulus_degree, py::arg("poly_modulus_degree"),
            SEAL_DOC("Set the degree of the polynomial modulus. In SEAL this must be a power of two."))
        .def("set_coeff_modulus", &EncryptionParameters::set_coeff_modulus, py::arg("coeff_modulus"),
            SEAL_DOC("Set the coefficient modulus as a list of distinct prime Modulus values."))
        .def("set_plain_modulus", py::overload_cast<const Modulus &>(&EncryptionParameters::set_plain_modulus),
            py::arg("plain_modulus"),
            SEAL_DOC("Set the plaintext modulus using a Modulus object."))
        .def("set_plain_modulus", py::overload_cast<std::uint64_t>(&EncryptionParameters::set_plain_modulus),
            py::arg("plain_modulus"),
            SEAL_DOC("Set the plaintext modulus from an integer value."))
        .def("scheme", &EncryptionParameters::scheme, SEAL_DOC("Return the selected encryption scheme."))
        .def("poly_modulus_degree", &EncryptionParameters::poly_modulus_degree, SEAL_DOC("Return the degree of the polynomial modulus."))
        .def("coeff_modulus", &EncryptionParameters::coeff_modulus, SEAL_DOC("Return the coefficient modulus chain."))
        .def("plain_modulus", &EncryptionParameters::plain_modulus, SEAL_DOC("Return the plaintext modulus."))
        .def("save", [](const EncryptionParameters &parms, std::string &path){
            std::ofstream out(path, std::ios::binary);
            parms.save(out);
            out.close();
        }, py::arg("path"),
            SEAL_DOC("Serialize the encryption parameters to a file."))
        .def("save", [](const EncryptionParameters &parms, std::string &path, compr_mode_type compr_mode){
            std::ofstream out(path, std::ios::binary);
            parms.save(out, compr_mode);
            out.close();
        }, py::arg("path"), py::arg("compr_mode"),
            SEAL_DOC("Serialize the encryption parameters to a file using the given compression mode."))
        .def("load", [](EncryptionParameters &parms, std::string &path){
            std::ifstream in(path, std::ios::binary);
            parms.load(in);
            in.close();
        }, py::arg("path"),
            SEAL_DOC("Load serialized encryption parameters from a file."))
        .def("load_bytes", [](EncryptionParameters &parms, py::bytes data){
            std::string raw = data;
            parms.load(reinterpret_cast<const seal_byte *>(raw.data()), raw.size());
        }, py::arg("data"),
            SEAL_DOC("Load serialized encryption parameters from a bytes object."))
        .def("save_size", py::overload_cast<compr_mode_type>(&EncryptionParameters::save_size, py::const_),
            py::arg("compr_mode")=Serialization::compr_mode_default,
            SEAL_DOC("Return the serialized size in bytes for the given compression mode."))
        .def("to_bytes", [](const EncryptionParameters &parms, compr_mode_type compr_mode){
            std::stringstream out(std::ios::binary | std::ios::out);
            parms.save(out, compr_mode);
            return py::bytes(out.str());
        }, py::arg("compr_mode")=Serialization::compr_mode_default,
            SEAL_DOC("Serialize the encryption parameters to a Python bytes object."))
        .def(py::pickle(
            [](const EncryptionParameters &parms){
                std::stringstream out(std::ios::binary | std::ios::out);
                parms.save(out);
                return py::make_tuple(py::bytes(out.str()));
            },
            [](py::tuple t){
                if (t.size() != 1)
                    throw std::runtime_error("(Pickle) Invalid input tuple!");
                std::string str = t[0].cast<std::string>();
                std::stringstream in(std::ios::binary | std::ios::in);
                in.str(str);
                EncryptionParameters parms;
                parms.load(in);
                return parms;
            }
        ));

    // modulus.h
    py::enum_<sec_level_type>(m, "sec_level_type", SEAL_DOC("HomomorphicEncryption.org standard security level."))
        .value("none", sec_level_type::none)
        .value("tc128", sec_level_type::tc128)
        .value("tc192", sec_level_type::tc192)
        .value("tc256", sec_level_type::tc256);

    // context.h
    py::enum_<EncryptionParameterQualifiers::error_type>(
        m, "error_type",
        SEAL_DOC("Reason why a set of encryption parameters is invalid."))
        .value("none", EncryptionParameterQualifiers::error_type::none)
        .value("success", EncryptionParameterQualifiers::error_type::success)
        .value("invalid_scheme", EncryptionParameterQualifiers::error_type::invalid_scheme)
        .value("invalid_coeff_modulus_size", EncryptionParameterQualifiers::error_type::invalid_coeff_modulus_size)
        .value("invalid_coeff_modulus_bit_count", EncryptionParameterQualifiers::error_type::invalid_coeff_modulus_bit_count)
        .value("invalid_coeff_modulus_no_ntt", EncryptionParameterQualifiers::error_type::invalid_coeff_modulus_no_ntt)
        .value("invalid_poly_modulus_degree", EncryptionParameterQualifiers::error_type::invalid_poly_modulus_degree)
        .value("invalid_poly_modulus_degree_non_power_of_two", EncryptionParameterQualifiers::error_type::invalid_poly_modulus_degree_non_power_of_two)
        .value("invalid_parameters_too_large", EncryptionParameterQualifiers::error_type::invalid_parameters_too_large)
        .value("invalid_parameters_insecure", EncryptionParameterQualifiers::error_type::invalid_parameters_insecure)
        .value("failed_creating_rns_base", EncryptionParameterQualifiers::error_type::failed_creating_rns_base)
        .value("invalid_plain_modulus_bit_count", EncryptionParameterQualifiers::error_type::invalid_plain_modulus_bit_count)
        .value("invalid_plain_modulus_coprimality", EncryptionParameterQualifiers::error_type::invalid_plain_modulus_coprimality)
        .value("invalid_plain_modulus_too_large", EncryptionParameterQualifiers::error_type::invalid_plain_modulus_too_large)
        .value("invalid_plain_modulus_nonzero", EncryptionParameterQualifiers::error_type::invalid_plain_modulus_nonzero)
        .value("failed_creating_rns_tool", EncryptionParameterQualifiers::error_type::failed_creating_rns_tool);

    // context.h
    py::class_<EncryptionParameterQualifiers, std::unique_ptr<EncryptionParameterQualifiers, py::nodelete>>(
        m, "EncryptionParameterQualifiers",
        SEAL_DOC("Stores pre-computed attributes and validation results for encryption parameters."))
        .def("parameters_set", &EncryptionParameterQualifiers::parameters_set,
            SEAL_DOC("Return True if the parameters were validated successfully."))
        .def_readwrite("parameter_error", &EncryptionParameterQualifiers::parameter_error,
            "Validation error code for the parameter set.")
        .def("parameter_error_name", &EncryptionParameterQualifiers::parameter_error_name,
            SEAL_DOC("Return the symbolic name of the validation error."))
        .def("parameter_error_message", &EncryptionParameterQualifiers::parameter_error_message,
            SEAL_DOC("Return a human-readable explanation of the validation error."))
        .def_readwrite("using_fft", &EncryptionParameterQualifiers::using_fft,
            "Whether FFT can be used for polynomial multiplication.")
        .def_readwrite("using_ntt", &EncryptionParameterQualifiers::using_ntt,
            "Whether NTT can be used for polynomial multiplication.")
        .def_readwrite("using_batching", &EncryptionParameterQualifiers::using_batching,
            "Whether SIMD batching is supported.")
        .def_readwrite("using_fast_plain_lift", &EncryptionParameterQualifiers::using_fast_plain_lift,
            "Whether fast plain lift is available.")
        .def_readwrite("using_descending_modulus_chain", &EncryptionParameterQualifiers::using_descending_modulus_chain,
            "Whether the coefficient modulus primes are in descending order.")
        .def_readwrite("sec_level", &EncryptionParameterQualifiers::sec_level,
            "Security level classification for the parameters.");

    // context.h
    py::class_<SEALContext::ContextData, std::shared_ptr<SEALContext::ContextData>>(
        m, "ContextData",
        SEAL_DOC("Pre-computation data associated with one specific parameter set in the modulus switching chain."))
        .def("parms", &SEALContext::ContextData::parms, SEAL_DOC("Return the encryption parameters for this context level."))
        .def("parms_id", &SEALContext::ContextData::parms_id, SEAL_DOC("Return the unique parameter identifier for this context level."))
        .def("qualifiers", &SEALContext::ContextData::qualifiers, SEAL_DOC("Return qualifiers derived from these parameters."))
        .def("total_coeff_modulus", &SEALContext::ContextData::total_coeff_modulus, SEAL_DOC("Return the product of all coefficient modulus primes."))
        .def("total_coeff_modulus_bit_count", &SEALContext::ContextData::total_coeff_modulus_bit_count, SEAL_DOC("Return the bit count of the total coefficient modulus."))
        .def("next_context_data", &SEALContext::ContextData::next_context_data, SEAL_DOC("Return the next lower level in the modulus switching chain."))
        .def("chain_index", &SEALContext::ContextData::chain_index, SEAL_DOC("Return the chain index for this context level."));

    // context.h
    py::class_<SEALContext, std::shared_ptr<SEALContext>>(
        m, "SEALContext",
        SEAL_DOC("Validates encryption parameters and stores heavy-weight pre-computations used by SEAL operations."))
        .def(py::init<const EncryptionParameters &, bool, sec_level_type>(),
            py::arg("parms"), py::arg("expand_mod_chain")=true, py::arg("sec_level")=sec_level_type::tc128,
            SEAL_DOC("Create a SEALContext from encryption parameters and optionally expand the modulus switching chain."))
        .def("get_context_data", &SEALContext::get_context_data, py::arg("parms_id"),
            SEAL_DOC("Return the ContextData for a specific parms_id."))
        .def("key_context_data", &SEALContext::key_context_data, SEAL_DOC("Return the key-level ContextData."))
        .def("first_context_data", &SEALContext::first_context_data, SEAL_DOC("Return the first data-level ContextData in the chain."))
        .def("last_context_data", &SEALContext::last_context_data, SEAL_DOC("Return the last valid ContextData in the chain."))
        .def("parameters_set", &SEALContext::parameters_set, SEAL_DOC("Return True if the parameters were validated successfully."))
        .def("parameter_error_name", &SEALContext::parameter_error_name, SEAL_DOC("Return the symbolic name of the validation result."))
        .def("parameter_error_message", &SEALContext::parameter_error_message, SEAL_DOC("Return a human-readable validation message."))
        .def("first_parms_id", &SEALContext::first_parms_id, SEAL_DOC("Return the parms_id for the first data-level parameters."))
        .def("last_parms_id", &SEALContext::last_parms_id, SEAL_DOC("Return the parms_id for the last valid parameters in the chain."))
        .def("using_keyswitching", &SEALContext::using_keyswitching, SEAL_DOC("Return True if the parameter chain supports key switching."))
        .def("from_cipher_str", [](const SEALContext &context, const std::string &str){
            Ciphertext cipher;
            std::stringstream in(std::ios::binary | std::ios::in);
            in.str(str);
            cipher.load(context, in);
            return cipher;
        }, py::arg("data"),
            SEAL_DOC("Deserialize a Ciphertext from a serialized bytes-like string."))
        .def("from_plain_str", [](const SEALContext &context, const std::string &str){
            Plaintext plain;
            std::stringstream in(std::ios::binary | std::ios::in);
            in.str(str);
            plain.load(context, in);
            return plain;
        }, py::arg("data"),
            SEAL_DOC("Deserialize a Plaintext from a serialized bytes-like string."))
        .def("from_secret_str", [](const SEALContext &context, const std::string &str){
            SecretKey secret;
            std::stringstream in(std::ios::binary | std::ios::in);
            in.str(str);
            secret.load(context, in);
            return secret;
        }, py::arg("data"),
            SEAL_DOC("Deserialize a SecretKey from a serialized bytes-like string."))
        .def("from_public_str", [](const SEALContext &context, const std::string &str){
            PublicKey public_;
            std::stringstream in(std::ios::binary | std::ios::in);
            in.str(str);
            public_.load(context, in);
            return public_;
        }, py::arg("data"),
            SEAL_DOC("Deserialize a PublicKey from a serialized bytes-like string."))
        .def("from_relin_str", [](const SEALContext &context, const std::string &str){
            RelinKeys relin;
            std::stringstream in(std::ios::binary | std::ios::in);
            in.str(str);
            relin.load(context, in);
            return relin;
        }, py::arg("data"),
            SEAL_DOC("Deserialize RelinKeys from a serialized bytes-like string."))
        .def("from_galois_str", [](const SEALContext &context, const std::string &str){
            GaloisKeys galois;
            std::stringstream in(std::ios::binary | std::ios::in);
            in.str(str);
            galois.load(context, in);
            return galois;
        }, py::arg("data"),
            SEAL_DOC("Deserialize GaloisKeys from a serialized bytes-like string."));

    // modulus.h
    py::class_<Modulus>(m, "Modulus", SEAL_DOC("Represents an integer modulus used in encryption parameters."))
        .def(py::init<std::uint64_t>(), py::arg("value"),
            SEAL_DOC("Construct a modulus from an unsigned 64-bit integer."))
        .def("bit_count", &Modulus::bit_count, SEAL_DOC("Return the bit length of the modulus."))
        .def("value", &Modulus::value, SEAL_DOC("Return the numeric value of the modulus."))
        .def("is_zero", &Modulus::is_zero, SEAL_DOC("Return True if the modulus is zero."))
        .def("is_prime", &Modulus::is_prime, SEAL_DOC("Return True if the modulus value is prime."))
        .def("reduce", &Modulus::reduce, py::arg("value"),
            SEAL_DOC("Reduce an integer modulo this modulus."));
        //save & load

    // modulus.h
    py::class_<CoeffModulus>(m, "CoeffModulus", SEAL_DOC("Factory helpers for constructing coefficient modulus chains."))
        .def_static("MaxBitCount", &CoeffModulus::MaxBitCount, py::arg("poly_modulus_degree"), py::arg("sec_level")=sec_level_type::tc128,
            SEAL_DOC("Return the maximum safe total bit count for the coefficient modulus."))
        .def_static("BFVDefault", &CoeffModulus::BFVDefault, py::arg("poly_modulus_degree"), py::arg("sec_level")=sec_level_type::tc128,
            SEAL_DOC("Return SEAL's default BFV/BGV coefficient modulus for the requested security level."))
        .def_static("Create", py::overload_cast<std::size_t, std::vector<int>>(&CoeffModulus::Create),
            py::arg("poly_modulus_degree"), py::arg("bit_sizes"),
            SEAL_DOC("Create a custom coefficient modulus chain with primes of the given bit sizes."))
        .def_static("Create", py::overload_cast<std::size_t, const Modulus &, std::vector<int>>(&CoeffModulus::Create),
            py::arg("poly_modulus_degree"), py::arg("plain_modulus"), py::arg("bit_sizes"),
            SEAL_DOC("Create a custom coefficient modulus chain tailored to batching/plain modulus constraints."));

    // modulus.h
    py::class_<PlainModulus>(m, "PlainModulus", SEAL_DOC("Factory helpers for constructing plaintext moduli."))
        .def_static("Batching", py::overload_cast<std::size_t, int>(&PlainModulus::Batching),
            py::arg("poly_modulus_degree"), py::arg("bit_size"),
            SEAL_DOC("Create one batching-compatible plaintext modulus with the given bit size."))
        .def_static("Batching", py::overload_cast<std::size_t, std::vector<int>>(&PlainModulus::Batching),
            py::arg("poly_modulus_degree"), py::arg("bit_sizes"),
            SEAL_DOC("Create batching-compatible plaintext moduli for the requested bit sizes."));

    // plaintext.h
    py::class_<Plaintext>(
        m, "Plaintext",
        SEAL_DOC("Stores a plaintext polynomial. In CKKS, plaintexts are typically kept in NTT form and also carry a scale."))
        .def(py::init<>(), SEAL_DOC("Construct an empty plaintext with no allocated data."))
        .def(py::init<std::size_t>(), py::arg("coeff_count"),
            SEAL_DOC("Construct a zero plaintext with the given coefficient count."))
        .def(py::init<std::size_t, std::size_t>(), py::arg("capacity"), py::arg("coeff_count"),
            SEAL_DOC("Construct a zero plaintext with explicit capacity and coefficient count."))
        .def(py::init<const std::string &>(), py::arg("hex_poly"),
            SEAL_DOC("Construct a plaintext from the hexadecimal polynomial format returned by to_string()."))
        .def(py::init<const Plaintext &>(), py::arg("copy"),
            SEAL_DOC("Construct a copy of an existing plaintext."))
        .def("set_zero", py::overload_cast<std::size_t, std::size_t>(&Plaintext::set_zero),
            py::arg("start_coeff"), py::arg("length"),
            SEAL_DOC("Set a range of coefficients to zero."))
        .def("set_zero", py::overload_cast<std::size_t>(&Plaintext::set_zero), py::arg("start_coeff"),
            SEAL_DOC("Set coefficients from start_coeff to the end to zero."))
        .def("set_zero", py::overload_cast<>(&Plaintext::set_zero),
            SEAL_DOC("Set all coefficients to zero."))
        .def("is_zero", &Plaintext::is_zero, SEAL_DOC("Return True if all coefficients are zero."))
        .def("capacity", &Plaintext::capacity, SEAL_DOC("Return the allocation capacity measured in coefficients."))
        .def("coeff_count", &Plaintext::coeff_count, SEAL_DOC("Return the number of coefficients stored in the plaintext."))
        .def("significant_coeff_count", &Plaintext::significant_coeff_count, SEAL_DOC("Return the number of significant coefficients."))
        .def("nonzero_coeff_count", &Plaintext::nonzero_coeff_count, SEAL_DOC("Return the number of non-zero coefficients."))
        .def("to_string", &Plaintext::to_string, SEAL_DOC("Return the plaintext polynomial formatted as a hexadecimal string."))
        .def("is_ntt_form", &Plaintext::is_ntt_form, SEAL_DOC("Return True if the plaintext is stored in NTT form."))
        .def("parms_id", py::overload_cast<>(&Plaintext::parms_id, py::const_),
            SEAL_DOC("Return the parms_id associated with this plaintext."))
        .def("scale", py::overload_cast<>(&Plaintext::scale, py::const_),
            SEAL_DOC("Return the CKKS scale attached to this plaintext."))
        .def("scale", [](Plaintext &plain, double scale){
            plain.scale() = scale;
        }, py::arg("scale"),
            SEAL_DOC("Set the CKKS scale attached to this plaintext."))
        .def("save", [](const Plaintext &plain, const std::string &path){
            std::ofstream out(path, std::ios::binary);
            plain.save(out);
            out.close();
        }, py::arg("path"),
            SEAL_DOC("Serialize the plaintext to a file."))
        .def("save", [](const Plaintext &plain, const std::string &path, compr_mode_type compr_mode){
            std::ofstream out(path, std::ios::binary);
            plain.save(out, compr_mode);
            out.close();
        }, py::arg("path"), py::arg("compr_mode"),
            SEAL_DOC("Serialize the plaintext to a file using the given compression mode."))
        .def("load", [](Plaintext &plain, const SEALContext &context, const std::string &path){
            std::ifstream in(path, std::ios::binary);
            plain.load(context, in);
            in.close();
        }, py::arg("context"), py::arg("path"),
            SEAL_DOC("Load a serialized plaintext from a file and validate it against the context."))
        .def("load_bytes", [](Plaintext &plain, const SEALContext &context, py::bytes data){
            std::string raw = data;
            plain.load(context, reinterpret_cast<const seal_byte *>(raw.data()), raw.size());
        }, py::arg("context"), py::arg("data"),
            SEAL_DOC("Load a serialized plaintext from a bytes object and validate it against the context."))
        .def("save_size", [](const Plaintext &plain){
            return plain.save_size();
        }, SEAL_DOC("Return the serialized size in bytes using the default compression mode."))
        .def("save_size", py::overload_cast<compr_mode_type>(&Plaintext::save_size, py::const_),
            py::arg("compr_mode")=Serialization::compr_mode_default,
            SEAL_DOC("Return the serialized size in bytes for the given compression mode."))
        .def("to_bytes", [](const Plaintext &plain, compr_mode_type compr_mode){
            std::stringstream out(std::ios::binary | std::ios::out);
            plain.save(out, compr_mode);
            return py::bytes(out.str());
        }, py::arg("compr_mode")=Serialization::compr_mode_default,
            SEAL_DOC("Serialize the plaintext to a Python bytes object."));

    // ciphertext.h
    py::class_<Ciphertext>(
        m, "Ciphertext",
        SEAL_DOC("Stores an encrypted value as two or more CRT polynomials together with parameter metadata."))
        .def(py::init<>(), SEAL_DOC("Construct an empty ciphertext with no allocated data."))
        .def(py::init<const SEALContext &>(), py::arg("context"),
            SEAL_DOC("Construct an empty ciphertext initialized for the highest data level in the context."))
        .def(py::init<const SEALContext &, parms_id_type>(), py::arg("context"), py::arg("parms_id"),
            SEAL_DOC("Construct an empty ciphertext initialized for a specific parms_id."))
        .def(py::init<const SEALContext &, parms_id_type, std::size_t>(),
            py::arg("context"), py::arg("parms_id"), py::arg("size_capacity"),
            SEAL_DOC("Construct an empty ciphertext with explicit polynomial capacity."))
        .def(py::init<const Ciphertext &>(), py::arg("copy"),
            SEAL_DOC("Construct a copy of an existing ciphertext."))
        .def("coeff_modulus_size", &Ciphertext::coeff_modulus_size, SEAL_DOC("Return the number of coefficient modulus primes."))
        .def("poly_modulus_degree", &Ciphertext::poly_modulus_degree, SEAL_DOC("Return the polynomial modulus degree."))
        .def("size", &Ciphertext::size, SEAL_DOC("Return the number of polynomials in the ciphertext."))
        .def("size_capacity", &Ciphertext::size_capacity, SEAL_DOC("Return the allocated ciphertext capacity measured in polynomials."))
        .def("is_transparent", &Ciphertext::is_transparent, SEAL_DOC("Return True if the ciphertext is transparent, which is generally insecure."))
        .def("is_ntt_form", py::overload_cast<>(&Ciphertext::is_ntt_form, py::const_),
            SEAL_DOC("Return True if the ciphertext is stored in NTT form."))
        .def("parms_id", py::overload_cast<>(&Ciphertext::parms_id, py::const_),
            SEAL_DOC("Return the parms_id associated with this ciphertext."))
        .def("scale", py::overload_cast<>(&Ciphertext::scale, py::const_),
            SEAL_DOC("Return the CKKS scale attached to this ciphertext."))
        .def("scale", [](Ciphertext &cipher, double scale){
            cipher.scale() = scale;
        }, py::arg("scale"),
            SEAL_DOC("Set the CKKS scale attached to this ciphertext."))
        .def("save", [](const Ciphertext &cipher, const std::string &path){
            std::ofstream out(path, std::ios::binary);
            cipher.save(out);
            out.close();
        }, py::arg("path"),
            SEAL_DOC("Serialize the ciphertext to a file."))
        .def("save", [](const Ciphertext &cipher, const std::string &path, compr_mode_type compr_mode){
            std::ofstream out(path, std::ios::binary);
            cipher.save(out, compr_mode);
            out.close();
        }, py::arg("path"), py::arg("compr_mode"),
            SEAL_DOC("Serialize the ciphertext to a file using the given compression mode."))
        .def("load", [](Ciphertext &cipher, const SEALContext &context, const std::string &path){
            std::ifstream in(path, std::ios::binary);
            cipher.load(context, in);
            in.close();
        }, py::arg("context"), py::arg("path"),
            SEAL_DOC("Load a serialized ciphertext from a file and validate it against the context."))
        .def("load_bytes", [](Ciphertext &cipher, const SEALContext &context, py::bytes data){
            std::string raw = data;
            cipher.load(context, reinterpret_cast<const seal_byte *>(raw.data()), raw.size());
        }, py::arg("context"), py::arg("data"),
            SEAL_DOC("Load a serialized ciphertext from a bytes object and validate it against the context."))
        .def("save_size", [](const Ciphertext &cipher){
            return cipher.save_size();
        }, SEAL_DOC("Return the serialized size in bytes using the default compression mode."))
        .def("save_size", py::overload_cast<compr_mode_type>(&Ciphertext::save_size, py::const_),
            py::arg("compr_mode")=Serialization::compr_mode_default,
            SEAL_DOC("Return the serialized size in bytes for the given compression mode."))
        .def("to_string", [](const Ciphertext &cipher, compr_mode_type compr_mode){
            std::stringstream out(std::ios::binary | std::ios::out);
            cipher.save(out, compr_mode);
            return py::bytes(out.str());
        }, py::arg("compr_mode")=Serialization::compr_mode_default,
            SEAL_DOC("Serialize the ciphertext to a Python bytes object."));

    // secretkey.h
    py::class_<SecretKey>(m, "SecretKey", SEAL_DOC("Stores the secret key used for decryption and symmetric encryption."))
        .def(py::init<>(), SEAL_DOC("Construct an empty secret key."))
        .def(py::init<const SecretKey &>(), py::arg("copy"),
            SEAL_DOC("Construct a copy of an existing secret key."))
        .def("parms_id", py::overload_cast<>(&SecretKey::parms_id, py::const_),
            SEAL_DOC("Return the parms_id associated with the secret key."))
        .def("save", [](const SecretKey &sk, const std::string &path){
            std::ofstream out(path, std::ios::binary);
            sk.save(out);
            out.close();
        }, py::arg("path"),
            SEAL_DOC("Serialize the secret key to a file."))
        .def("load", [](SecretKey &sk, const SEALContext &context, const std::string &path){
            std::ifstream in(path, std::ios::binary);
            sk.load(context, in);
            in.close();
        }, py::arg("context"), py::arg("path"),
            SEAL_DOC("Load a serialized secret key from a file."))
        .def("to_string", [](const SecretKey &secret){
            std::stringstream out(std::ios::binary | std::ios::out);
            secret.save(out);
            return py::bytes(out.str());
        }, SEAL_DOC("Serialize the secret key to a Python bytes object."));

    // publickey.h
    py::class_<PublicKey>(m, "PublicKey", SEAL_DOC("Stores the public key used for public-key encryption."))
        .def(py::init<>(), SEAL_DOC("Construct an empty public key."))
        .def(py::init<const PublicKey &>(), py::arg("copy"),
            SEAL_DOC("Construct a copy of an existing public key."))
        .def("parms_id", py::overload_cast<>(&PublicKey::parms_id, py::const_),
            SEAL_DOC("Return the parms_id associated with the public key."))
        .def("save", [](const PublicKey &pk, const std::string &path){
            std::ofstream out(path, std::ios::binary);
            pk.save(out);
            out.close();
        }, py::arg("path"),
            SEAL_DOC("Serialize the public key to a file."))
        .def("load", [](PublicKey &pk, const SEALContext &context, const std::string &path){
            std::ifstream in(path, std::ios::binary);
            pk.load(context, in);
            in.close();
        }, py::arg("context"), py::arg("path"),
            SEAL_DOC("Load a serialized public key from a file."))
        .def("to_string", [](const PublicKey &public_){
            std::stringstream out(std::ios::binary | std::ios::out);
            public_.save(out);
            return py::bytes(out.str());
        }, SEAL_DOC("Serialize the public key to a Python bytes object."));

    // kswitchkeys.h
    py::class_<KSwitchKeys>(m, "KSwitchKeys", SEAL_DOC("Base container for key switching key material."))
        .def(py::init<>(), SEAL_DOC("Construct an empty key switching key container."))
        .def(py::init<const KSwitchKeys &>(), py::arg("copy"),
            SEAL_DOC("Construct a copy of an existing key switching key container."))
        .def("size", &KSwitchKeys::size, SEAL_DOC("Return the number of stored key switching key sets."))
        .def("parms_id", py::overload_cast<>(&KSwitchKeys::parms_id, py::const_),
            SEAL_DOC("Return the parms_id associated with this key set."))
        .def("save", [](const KSwitchKeys &ksk, const std::string &path){
            std::ofstream out(path, std::ios::binary);
            ksk.save(out);
            out.close();
        }, py::arg("path"),
            SEAL_DOC("Serialize the key switching keys to a file."))
        .def("load", [](KSwitchKeys &ksk, const SEALContext &context, const std::string &path){
            std::ifstream in(path, std::ios::binary);
            ksk.load(context, in);
            in.close();
        }, py::arg("context"), py::arg("path"),
            SEAL_DOC("Load serialized key switching keys from a file."));

    // relinkeys.h
    py::class_<RelinKeys, KSwitchKeys>(m, "RelinKeys", SEAL_DOC("Relinearization keys used to shrink ciphertext size after multiplication."))
        .def(py::init<>(), SEAL_DOC("Construct an empty set of relinearization keys."))
        .def(py::init<const RelinKeys::KSwitchKeys &>(), py::arg("copy"),
            SEAL_DOC("Construct relinearization keys from a key switching key base object."))
        .def("size", &RelinKeys::KSwitchKeys::size, SEAL_DOC("Return the number of stored relinearization key sets."))
        .def("parms_id", py::overload_cast<>(&RelinKeys::KSwitchKeys::parms_id, py::const_),
            SEAL_DOC("Return the parms_id associated with these relinearization keys."))
        .def_static("get_index", &RelinKeys::get_index, py::arg("key_power"),
            SEAL_DOC("Map a key power to the internal storage index used by SEAL."))
        .def("has_key", &RelinKeys::has_key, py::arg("key_power"),
            SEAL_DOC("Return True if a relinearization key exists for the given key power."))
        .def("save", [](const RelinKeys &rk, const std::string &path){
            std::ofstream out(path, std::ios::binary);
            rk.save(out);
            out.close();
        }, py::arg("path"),
            SEAL_DOC("Serialize the relinearization keys to a file."))
        .def("load", [](RelinKeys &rk, const SEALContext &context, const std::string &path){
            std::ifstream in(path, std::ios::binary);
            rk.load(context, in);
            in.close();
        }, py::arg("context"), py::arg("path"),
            SEAL_DOC("Load serialized relinearization keys from a file."))
        .def("to_string", [](const RelinKeys &relin){
            std::stringstream out(std::ios::binary | std::ios::out);
            relin.save(out);
            return py::bytes(out.str());
        }, SEAL_DOC("Serialize the relinearization keys to a Python bytes object."));

    // galoiskeys.h
    py::class_<GaloisKeys, KSwitchKeys>(m, "GaloisKeys", SEAL_DOC("Galois keys used for rotations and CKKS complex conjugation."))
        .def(py::init<>(), SEAL_DOC("Construct an empty set of Galois keys."))
        .def(py::init<const GaloisKeys::KSwitchKeys &>(), py::arg("copy"),
            SEAL_DOC("Construct Galois keys from a key switching key base object."))
        .def("size", &GaloisKeys::KSwitchKeys::size, SEAL_DOC("Return the number of stored Galois key sets."))
        .def("parms_id", py::overload_cast<>(&GaloisKeys::KSwitchKeys::parms_id, py::const_),
            SEAL_DOC("Return the parms_id associated with these Galois keys."))
        .def_static("get_index", &GaloisKeys::get_index, py::arg("galois_elt"),
            SEAL_DOC("Map a Galois element to the internal storage index used by SEAL."))
        .def("has_key", &GaloisKeys::has_key, py::arg("galois_elt"),
            SEAL_DOC("Return True if a Galois key exists for the given Galois element."))
        .def("save", [](const GaloisKeys &gk, const std::string &path){
            std::ofstream out(path, std::ios::binary);
            gk.save(out);
            out.close();
        }, py::arg("path"),
            SEAL_DOC("Serialize the Galois keys to a file."))
        .def("load", [](GaloisKeys &gk, const SEALContext &context, const std::string &path){
            std::ifstream in(path, std::ios::binary);
            gk.load(context, in);
            in.close();
        }, py::arg("context"), py::arg("path"),
            SEAL_DOC("Load serialized Galois keys from a file."))
        .def("to_string", [](const GaloisKeys &galois){
            std::stringstream out(std::ios::binary | std::ios::out);
            galois.save(out);
            return py::bytes(out.str());
        }, SEAL_DOC("Serialize the Galois keys to a Python bytes object."));

    // keygenerator.h
    py::class_<KeyGenerator>(m, "KeyGenerator", SEAL_DOC("Generates secret, public, relinearization, and Galois keys for a SEALContext."))
        .def(py::init<const SEALContext &>(), py::arg("context"),
            SEAL_DOC("Create a key generator and generate a fresh secret key."))
        .def(py::init<const SEALContext &, const SecretKey &>(), py::arg("context"), py::arg("secret_key"),
            SEAL_DOC("Create a key generator from an existing secret key."))
        .def("secret_key", &KeyGenerator::secret_key, SEAL_DOC("Return the secret key managed by this generator."))
        .def("create_public_key", py::overload_cast<PublicKey &>(&KeyGenerator::create_public_key, py::const_), py::arg("destination"),
            SEAL_DOC("Generate a public key and store it in destination."))
        .def("create_relin_keys", py::overload_cast<RelinKeys &>(&KeyGenerator::create_relin_keys), py::arg("destination"),
            SEAL_DOC("Generate relinearization keys and store them in destination."))
        .def("create_galois_keys", py::overload_cast<const std::vector<int> &, GaloisKeys &>(&KeyGenerator::create_galois_keys),
            py::arg("steps"), py::arg("destination"),
            SEAL_DOC("Generate Galois keys for the requested rotation steps and store them in destination."))
        .def("create_galois_keys", py::overload_cast<GaloisKeys &>(&KeyGenerator::create_galois_keys), py::arg("destination"),
            SEAL_DOC("Generate all supported Galois keys and store them in destination."))
        .def("create_public_key", [](KeyGenerator &keygen){
            PublicKey pk;
            keygen.create_public_key(pk);
            return pk;
        }, SEAL_DOC("Generate and return a new public key."))
        .def("create_relin_keys", [](KeyGenerator &keygen){
            RelinKeys rk;
            keygen.create_relin_keys(rk);
            return rk;
        }, SEAL_DOC("Generate and return relinearization keys."))
        .def("create_galois_keys", [](KeyGenerator &keygen){
            GaloisKeys gk;
            keygen.create_galois_keys(gk);
            return gk;
        }, SEAL_DOC("Generate and return all supported Galois keys."));

    // encryptor.h
    py::class_<Encryptor>(m, "Encryptor", SEAL_DOC("Encrypts plaintexts using a public key or a secret key."))
        .def(py::init<const SEALContext &, const PublicKey &>(), py::arg("context"), py::arg("public_key"),
            SEAL_DOC("Create an encryptor configured for public-key encryption."))
        .def(py::init<const SEALContext &, const SecretKey &>(), py::arg("context"), py::arg("secret_key"),
            SEAL_DOC("Create an encryptor configured for secret-key encryption."))
        .def(py::init<const SEALContext &, const PublicKey &, const SecretKey &>(),
            py::arg("context"), py::arg("public_key"), py::arg("secret_key"),
            SEAL_DOC("Create an encryptor configured with both public and secret keys."))
        .def("set_public_key", &Encryptor::set_public_key, py::arg("public_key"),
            SEAL_DOC("Set or replace the public key used for encryption."))
        .def("set_secret_key", &Encryptor::set_secret_key, py::arg("secret_key"),
            SEAL_DOC("Set or replace the secret key used for symmetric encryption."))
        .def("encrypt_zero", [](const Encryptor &encryptor){
            Ciphertext encrypted;
            encryptor.encrypt_zero(encrypted);
            return encrypted;
        }, SEAL_DOC("Encrypt the zero plaintext at the first data level and return the ciphertext."))
        .def("encrypt_zero", [](const Encryptor &encryptor, Ciphertext &destination){
            encryptor.encrypt_zero(destination);
        }, py::arg("destination"),
            SEAL_DOC("Encrypt the zero plaintext at the first data level into destination."))
        .def("encrypt_zero", [](const Encryptor &encryptor, parms_id_type parms_id){
            Ciphertext encrypted;
            encryptor.encrypt_zero(parms_id, encrypted);
            return encrypted;
        }, py::arg("parms_id"),
            SEAL_DOC("Encrypt the zero plaintext for the specified parms_id and return the ciphertext."))
        .def("encrypt_zero", [](const Encryptor &encryptor, parms_id_type parms_id, Ciphertext &destination){
            encryptor.encrypt_zero(parms_id, destination);
        }, py::arg("parms_id"), py::arg("destination"),
            SEAL_DOC("Encrypt the zero plaintext for the specified parms_id into destination."))
        .def("encrypt", [](const Encryptor &encryptor, const Plaintext &plain){
            Ciphertext encrypted;
            encryptor.encrypt(plain, encrypted);
            return encrypted;
        }, py::arg("plain"),
            SEAL_DOC("Encrypt a plaintext with the public key and return the ciphertext."))
        .def("encrypt", [](const Encryptor &encryptor, const Plaintext &plain, Ciphertext &destination){
            encryptor.encrypt(plain, destination);
        }, py::arg("plain"), py::arg("destination"),
            SEAL_DOC("Encrypt a plaintext with the public key into destination."))
        .def("encrypt_symmetric", [](const Encryptor &encryptor, const Plaintext &plain){
            Ciphertext encrypted;
            encryptor.encrypt_symmetric(plain, encrypted);
            return encrypted;
        }, py::arg("plain"),
            SEAL_DOC("Encrypt a plaintext with the secret key and return the ciphertext."))
        .def("encrypt_symmetric", [](const Encryptor &encryptor, const Plaintext &plain, Ciphertext &destination){
            encryptor.encrypt_symmetric(plain, destination);
        }, py::arg("plain"), py::arg("destination"),
            SEAL_DOC("Encrypt a plaintext with the secret key into destination."));

    // evaluator.h
    py::class_<Evaluator>(m, "Evaluator", SEAL_DOC("Applies homomorphic operations to ciphertexts and plaintexts."))
        .def(py::init<const SEALContext &>(), py::arg("context"),
            SEAL_DOC("Create an evaluator for ciphertext operations under the given context."))
        .def("negate_inplace", &Evaluator::negate_inplace, py::arg("encrypted"),
            SEAL_DOC("Negate a ciphertext in place."))
        .def("negate", [](Evaluator &evaluator, const Ciphertext &encrypted1){
            Ciphertext destination;
            evaluator.negate(encrypted1, destination);
            return destination;
        }, py::arg("encrypted"),
            SEAL_DOC("Negate a ciphertext and return the result."))
        .def("add_inplace", &Evaluator::add_inplace, py::arg("encrypted1"), py::arg("encrypted2"),
            SEAL_DOC("Add two ciphertexts and store the result in encrypted1."))
        .def("add", [](Evaluator &evaluator, const Ciphertext &encrypted1, const Ciphertext &encrypted2){
            Ciphertext destination;
            evaluator.add(encrypted1, encrypted2, destination);
            return destination;
        }, py::arg("encrypted1"), py::arg("encrypted2"),
            SEAL_DOC("Add two ciphertexts and return the result."))
        .def("add_many", [](Evaluator &evaluator, const std::vector<Ciphertext> &encrypteds){
            Ciphertext destination;
            evaluator.add_many(encrypteds, destination);
            return destination;
        }, py::arg("encrypteds"),
            SEAL_DOC("Add many ciphertexts together and return the sum."))
        .def("sub_inplace", &Evaluator::sub_inplace, py::arg("encrypted1"), py::arg("encrypted2"),
            SEAL_DOC("Subtract encrypted2 from encrypted1 in place."))
        .def("sub", [](Evaluator &evaluator, const Ciphertext &encrypted1, const Ciphertext &encrypted2){
            Ciphertext destination;
            evaluator.sub(encrypted1, encrypted2, destination);
            return destination;
        }, py::arg("encrypted1"), py::arg("encrypted2"),
            SEAL_DOC("Subtract two ciphertexts and return the result."))
        .def("multiply_inplace", [](Evaluator &evaluator, Ciphertext &encrypted1, const Ciphertext &encrypted2){
            evaluator.multiply_inplace(encrypted1, encrypted2);
        }, py::arg("encrypted1"), py::arg("encrypted2"),
            SEAL_DOC("Multiply two ciphertexts and store the result in encrypted1."))
        .def("multiply", [](Evaluator &evaluator, const Ciphertext &encrypted1, const Ciphertext &encrypted2){
            Ciphertext destination;
            evaluator.multiply(encrypted1, encrypted2, destination);
            return destination;
        }, py::arg("encrypted1"), py::arg("encrypted2"),
            SEAL_DOC("Multiply two ciphertexts and return the result."))
        .def("square_inplace", [](Evaluator &evaluator, Ciphertext &encrypted1){
            evaluator.square_inplace(encrypted1);
        }, py::arg("encrypted"),
            SEAL_DOC("Square a ciphertext in place."))
        .def("square", [](Evaluator &evaluator, const Ciphertext &encrypted1){
            Ciphertext destination;
            evaluator.square(encrypted1, destination);
            return destination;
        }, py::arg("encrypted"),
            SEAL_DOC("Square a ciphertext and return the result."))
        .def("relinearize_inplace", [](Evaluator &evaluator, Ciphertext &encrypted1, const RelinKeys &relin_keys){
            evaluator.relinearize_inplace(encrypted1, relin_keys);
        }, py::arg("encrypted"), py::arg("relin_keys"),
            SEAL_DOC("Relinearize a ciphertext in place using relinearization keys."))
        .def("relinearize", [](Evaluator &evaluator, const Ciphertext &encrypted1, const RelinKeys &relin_keys){
            Ciphertext destination;
            evaluator.relinearize(encrypted1, relin_keys, destination);
            return destination;
        }, py::arg("encrypted"), py::arg("relin_keys"),
            SEAL_DOC("Relinearize a ciphertext and return the result."))
        .def("mod_switch_to_next", [](Evaluator &evaluator, const Ciphertext &encrypted){
            Ciphertext destination;
            evaluator.mod_switch_to_next(encrypted, destination);
            return destination;
        }, py::arg("encrypted"),
            SEAL_DOC("Mod-switch a ciphertext to the next level in the modulus chain and return the result."))
        .def("mod_switch_to_next_inplace", [](Evaluator &evaluator, Ciphertext &encrypted){
            evaluator.mod_switch_to_next_inplace(encrypted);
        }, py::arg("encrypted"),
            SEAL_DOC("Mod-switch a ciphertext to the next level in place."))
        .def("mod_switch_to_next_inplace", py::overload_cast<Plaintext &>(&Evaluator::mod_switch_to_next_inplace, py::const_),
            py::arg("plain"),
            SEAL_DOC("Mod-switch a plaintext to the next level in place."))
        .def("mod_switch_to_next", [](Evaluator &evaluator, const Plaintext &plain){
            Plaintext destination;
            evaluator.mod_switch_to_next(plain, destination);
            return destination;
        }, py::arg("plain"),
            SEAL_DOC("Mod-switch a plaintext to the next level and return the result."))
        .def("mod_switch_to_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, parms_id_type parms_id){
            evaluator.mod_switch_to_inplace(encrypted, parms_id);
        }, py::arg("encrypted"), py::arg("parms_id"),
            SEAL_DOC("Mod-switch a ciphertext in place to the specified parms_id."))
        .def("mod_switch_to", [](Evaluator &evaluator, const Ciphertext &encrypted, parms_id_type parms_id){
            Ciphertext destination;
            evaluator.mod_switch_to(encrypted, parms_id, destination);
            return destination;
        }, py::arg("encrypted"), py::arg("parms_id"),
            SEAL_DOC("Mod-switch a ciphertext to the specified parms_id and return the result."))
        .def("mod_switch_to_inplace", py::overload_cast<Plaintext &, parms_id_type>(&Evaluator::mod_switch_to_inplace, py::const_),
            py::arg("plain"), py::arg("parms_id"),
            SEAL_DOC("Mod-switch a plaintext in place to the specified parms_id."))
        .def("mod_switch_to", [](Evaluator &evaluator, const Plaintext &plain, parms_id_type parms_id){
            Plaintext destination;
            evaluator.mod_switch_to(plain, parms_id, destination);
            return destination;
        }, py::arg("plain"), py::arg("parms_id"),
            SEAL_DOC("Mod-switch a plaintext to the specified parms_id and return the result."))
        .def("rescale_to_next", [](Evaluator &evaluator, const Ciphertext &encrypted){
            Ciphertext destination;
            evaluator.rescale_to_next(encrypted, destination);
            return destination;
        }, py::arg("encrypted"),
            SEAL_DOC("Rescale a CKKS ciphertext to the next level and return the result."))
        .def("rescale_to_next_inplace", [](Evaluator &evaluator, Ciphertext &encrypted){
            evaluator.rescale_to_next_inplace(encrypted);
        }, py::arg("encrypted"),
            SEAL_DOC("Rescale a CKKS ciphertext to the next level in place."))
        .def("rescale_to_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, parms_id_type parms_id){
            evaluator.rescale_to_inplace(encrypted, parms_id);
        }, py::arg("encrypted"), py::arg("parms_id"),
            SEAL_DOC("Rescale a CKKS ciphertext in place to the specified parms_id."))
        .def("rescale_to", [](Evaluator &evaluator, const Ciphertext &encrypted, parms_id_type parms_id){
            Ciphertext destination;
            evaluator.rescale_to(encrypted, parms_id, destination);
            return destination;
        }, py::arg("encrypted"), py::arg("parms_id"),
            SEAL_DOC("Rescale a CKKS ciphertext to the specified parms_id and return the result."))
        .def("multiply_many", [](Evaluator &evaluator,  const std::vector<Ciphertext> &encrypteds, const RelinKeys &relin_keys){
            Ciphertext destination;
            evaluator.multiply_many(encrypteds, relin_keys, destination);
            return destination;
        }, py::arg("encrypteds"), py::arg("relin_keys"),
            SEAL_DOC("Multiply many ciphertexts together and return the result."))
        .def("exponentiate_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, std::uint64_t exponent, const RelinKeys &relin_keys){
            evaluator.exponentiate_inplace(encrypted, exponent, relin_keys);
        }, py::arg("encrypted"), py::arg("exponent"), py::arg("relin_keys"),
            SEAL_DOC("Raise a ciphertext to a power in place using repeated multiplication and relinearization."))
        .def("exponentiate", [](Evaluator &evaluator,  const Ciphertext &encrypted, std::uint64_t exponent, const RelinKeys &relin_keys){
            Ciphertext destination;
            evaluator.exponentiate(encrypted, exponent, relin_keys, destination);
            return destination;
        }, py::arg("encrypted"), py::arg("exponent"), py::arg("relin_keys"),
            SEAL_DOC("Raise a ciphertext to a power and return the result."))
        .def("add_plain_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, const Plaintext &plain){
            evaluator.add_plain_inplace(encrypted, plain);
        }, py::arg("encrypted"), py::arg("plain"),
            SEAL_DOC("Add a plaintext to a ciphertext in place."))
        .def("add_plain", [](Evaluator &evaluator, const Ciphertext &encrypted, const Plaintext &plain){
            Ciphertext destination;
            evaluator.add_plain(encrypted, plain, destination);
            return destination;
        }, py::arg("encrypted"), py::arg("plain"),
            SEAL_DOC("Add a plaintext to a ciphertext and return the result."))
        .def("sub_plain_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, const Plaintext &plain){
            evaluator.sub_plain_inplace(encrypted, plain);
        }, py::arg("encrypted"), py::arg("plain"),
            SEAL_DOC("Subtract a plaintext from a ciphertext in place."))
        .def("sub_plain", [](Evaluator &evaluator, const Ciphertext &encrypted, const Plaintext &plain){
            Ciphertext destination;
            evaluator.sub_plain(encrypted, plain, destination);
            return destination;
        }, py::arg("encrypted"), py::arg("plain"),
            SEAL_DOC("Subtract a plaintext from a ciphertext and return the result."))
        .def("multiply_plain_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, const Plaintext &plain){
            evaluator.multiply_plain_inplace(encrypted, plain);
        }, py::arg("encrypted"), py::arg("plain"),
            SEAL_DOC("Multiply a ciphertext by a plaintext in place."))
        .def("multiply_plain", [](Evaluator &evaluator, const Ciphertext &encrypted, const Plaintext &plain){
            Ciphertext destination;
            evaluator.multiply_plain(encrypted, plain, destination);
            return destination;
        }, py::arg("encrypted"), py::arg("plain"),
            SEAL_DOC("Multiply a ciphertext by a plaintext and return the result."))
        .def("transform_to_ntt_inplace", [](Evaluator &evaluator, Plaintext &plain, parms_id_type parms_id){
            evaluator.transform_to_ntt_inplace(plain,parms_id);
        }, py::arg("plain"), py::arg("parms_id"),
            SEAL_DOC("Transform a plaintext to NTT form in place."))
        .def("transform_to_ntt", [](Evaluator &evaluator, const Plaintext &plain, parms_id_type parms_id){
            Plaintext destination_ntt;
            evaluator.transform_to_ntt(plain, parms_id, destination_ntt);
            return destination_ntt;
        }, py::arg("plain"), py::arg("parms_id"),
            SEAL_DOC("Transform a plaintext to NTT form and return the result."))
        .def("transform_to_ntt_inplace", py::overload_cast<Ciphertext &>(&Evaluator::transform_to_ntt_inplace, py::const_),
            py::arg("encrypted"),
            SEAL_DOC("Transform a ciphertext to NTT form in place."))
        .def("transform_to_ntt", [](Evaluator &evaluator, const Ciphertext &encrypted){
            Ciphertext destination_ntt;
            evaluator.transform_to_ntt(encrypted, destination_ntt);
            return destination_ntt;
        }, py::arg("encrypted"),
            SEAL_DOC("Transform a ciphertext to NTT form and return the result."))
        .def("transform_from_ntt_inplace", &Evaluator::transform_from_ntt_inplace, py::arg("encrypted_ntt"),
            SEAL_DOC("Transform an NTT-form ciphertext back to coefficient form in place."))
        .def("transform_from_ntt", [](Evaluator &evaluator, const Ciphertext &encrypted_ntt){
            Ciphertext destination;
            evaluator.transform_from_ntt(encrypted_ntt, destination);
            return destination;
        }, py::arg("encrypted_ntt"),
            SEAL_DOC("Transform an NTT-form ciphertext back to coefficient form and return the result."))
        .def("apply_galois_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, std::uint32_t galois_elt, const GaloisKeys &galois_keys){
            evaluator.apply_galois_inplace(encrypted, galois_elt, galois_keys);
        }, py::arg("encrypted"), py::arg("galois_elt"), py::arg("galois_keys"),
            SEAL_DOC("Apply a Galois automorphism to a ciphertext in place."))
        .def("apply_galois", [](Evaluator &evaluator, const Ciphertext &encrypted, std::uint32_t galois_elt, const GaloisKeys &galois_keys){
            Ciphertext destination;
            evaluator.apply_galois(encrypted, galois_elt, galois_keys, destination);
            return destination;
        }, py::arg("encrypted"), py::arg("galois_elt"), py::arg("galois_keys"),
            SEAL_DOC("Apply a Galois automorphism to a ciphertext and return the result."))
        .def("rotate_rows_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys){
            evaluator.rotate_rows_inplace(encrypted, steps, galois_keys);
        }, py::arg("encrypted"), py::arg("steps"), py::arg("galois_keys"),
            SEAL_DOC("Rotate BFV/BGV batching rows in place."))
        .def("rotate_rows", [](Evaluator &evaluator, const Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys){
            Ciphertext destination;
            evaluator.rotate_rows(encrypted, steps, galois_keys, destination);
            return destination;
        }, py::arg("encrypted"), py::arg("steps"), py::arg("galois_keys"),
            SEAL_DOC("Rotate BFV/BGV batching rows and return the result."))
        .def("rotate_columns_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, const GaloisKeys &galois_keys){
            evaluator.rotate_columns_inplace(encrypted, galois_keys);
        }, py::arg("encrypted"), py::arg("galois_keys"),
            SEAL_DOC("Rotate BFV/BGV batching columns in place."))
        .def("rotate_columns", [](Evaluator &evaluator, const Ciphertext &encrypted, const GaloisKeys &galois_keys){
            Ciphertext destination;
            evaluator.rotate_columns(encrypted, galois_keys, destination);
            return destination;
        }, py::arg("encrypted"), py::arg("galois_keys"),
            SEAL_DOC("Rotate BFV/BGV batching columns and return the result."))
        .def("rotate_vector_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys){
            evaluator.rotate_vector_inplace(encrypted, steps, galois_keys);
        }, py::arg("encrypted"), py::arg("steps"), py::arg("galois_keys"),
            SEAL_DOC("Rotate a CKKS vector in place."))
        .def("rotate_vector", [](Evaluator &evaluator, const Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys){
            Ciphertext destination;
            evaluator.rotate_vector(encrypted, steps, galois_keys, destination);
            return destination;
        }, py::arg("encrypted"), py::arg("steps"), py::arg("galois_keys"),
            SEAL_DOC("Rotate a CKKS vector and return the result."))
        .def("complex_conjugate_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, const GaloisKeys &galois_keys){
            evaluator.complex_conjugate_inplace(encrypted, galois_keys);
        }, py::arg("encrypted"), py::arg("galois_keys"),
            SEAL_DOC("Apply CKKS complex conjugation in place."))
        .def("complex_conjugate", [](Evaluator &evaluator, const Ciphertext &encrypted, const GaloisKeys &galois_keys){
            Ciphertext destination;
            evaluator.complex_conjugate(encrypted, galois_keys, destination);
            return destination;
        }, py::arg("encrypted"), py::arg("galois_keys"),
            SEAL_DOC("Apply CKKS complex conjugation and return the result."));

    // ckks.h
    py::class_<CKKSEncoder>(m, "CKKSEncoder", SEAL_DOC("Encodes floating-point and complex vectors into CKKS plaintext polynomials."))
        .def(py::init<const SEALContext &>(), py::arg("context"),
            SEAL_DOC("Create a CKKS encoder for the given context."))
        .def("slot_count", &CKKSEncoder::slot_count, SEAL_DOC("Return the number of SIMD slots available for CKKS encoding."))
        .def("encode_complex", [](CKKSEncoder &encoder, const std::vector<std::complex<double>> &values, double scale, Plaintext &destination){
            encoder.encode(values, scale, destination);
        }, py::arg("values"), py::arg("scale"), py::arg("destination"),
            SEAL_DOC("Encode a vector of complex values into destination."))
        .def("encode", [](CKKSEncoder &encoder, const std::vector<double> &values, double scale, Plaintext &destination){
            encoder.encode(values, scale, destination);
        }, py::arg("values"), py::arg("scale"), py::arg("destination"),
            SEAL_DOC("Encode a vector of real values into destination."))
        .def("encode_complex", [](CKKSEncoder &encoder, py::array_t<std::complex<double>> values, double scale){
            py::buffer_info buf = values.request();
            if (buf.ndim == 0)
            {
                auto *ptr = static_cast<std::complex<double> *>(buf.ptr);
                Plaintext pt;
                encoder.encode(ptr[0], scale, pt);
                return pt;
            }
            if (buf.ndim != 1)
                throw std::runtime_error("E101: Number of dimensions must be one");

            auto *ptr = static_cast<std::complex<double> *>(buf.ptr);
            std::vector<std::complex<double>> vec(static_cast<std::size_t>(buf.shape[0]));

            for (py::ssize_t i = 0; i < buf.shape[0]; i++)
                vec[static_cast<std::size_t>(i)] = ptr[i];

            Plaintext pt;
            encoder.encode(vec, scale, pt);
            return pt;
        }, py::arg("values"), py::arg("scale"),
            SEAL_DOC("Encode a NumPy array or scalar of complex values and return the plaintext."))
        .def("encode_complex", [](CKKSEncoder &encoder, py::array_t<std::complex<double>> values, double scale, Plaintext &destination){
            py::buffer_info buf = values.request();
            if (buf.ndim == 0)
            {
                auto *ptr = static_cast<std::complex<double> *>(buf.ptr);
                encoder.encode(ptr[0], scale, destination);
                return;
            }
            if (buf.ndim != 1)
                throw std::runtime_error("E101: Number of dimensions must be one");

            auto *ptr = static_cast<std::complex<double> *>(buf.ptr);
            std::vector<std::complex<double>> vec(static_cast<std::size_t>(buf.shape[0]));

            for (py::ssize_t i = 0; i < buf.shape[0]; i++)
                vec[static_cast<std::size_t>(i)] = ptr[i];

            encoder.encode(vec, scale, destination);
        }, py::arg("values"), py::arg("scale"), py::arg("destination"),
            SEAL_DOC("Encode a NumPy array or scalar of complex values into destination."))
        .def("encode", [](CKKSEncoder &encoder, py::array_t<double> values, double scale){
            py::buffer_info buf = values.request();
            if (buf.ndim != 1)
                throw std::runtime_error("E101: Number of dimensions must be one");

            double *ptr = (double *)buf.ptr;
            std::vector<double> vec(buf.shape[0]);

            for (auto i = 0; i < buf.shape[0]; i++)
                vec[i] = ptr[i];

            Plaintext pt;
            encoder.encode(vec, scale, pt);
            return pt;
        }, py::arg("values"), py::arg("scale"),
            SEAL_DOC("Encode a one-dimensional NumPy array of real values and return the plaintext."))
        .def("encode_complex", [](CKKSEncoder &encoder, py::iterable values, double scale){
            std::vector<std::complex<double>> vec;
            vec.reserve(py::len(values));
            for (const auto &value : values)
                vec.push_back(py::cast<std::complex<double>>(value));

            Plaintext pt;
            encoder.encode(vec, scale, pt);
            return pt;
        }, py::arg("values"), py::arg("scale"),
            SEAL_DOC("Encode an iterable of complex values and return the plaintext."))
        .def("encode_complex", [](CKKSEncoder &encoder, py::iterable values, double scale, Plaintext &destination){
            std::vector<std::complex<double>> vec;
            vec.reserve(py::len(values));
            for (const auto &value : values)
                vec.push_back(py::cast<std::complex<double>>(value));
            encoder.encode(vec, scale, destination);
        }, py::arg("values"), py::arg("scale"), py::arg("destination"),
            SEAL_DOC("Encode an iterable of complex values into destination."))
        .def("encode", [](CKKSEncoder &encoder, py::iterable values, double scale){
            std::vector<double> vec;
            vec.reserve(py::len(values));
            for (const auto &value : values)
                vec.push_back(py::cast<double>(value));

            Plaintext pt;
            encoder.encode(vec, scale, pt);
            return pt;
        }, py::arg("values"), py::arg("scale"),
            SEAL_DOC("Encode an iterable of real values and return the plaintext."))
        .def("encode", [](CKKSEncoder &encoder, py::iterable values, double scale, Plaintext &destination){
            std::vector<double> vec;
            vec.reserve(py::len(values));
            for (const auto &value : values)
                vec.push_back(py::cast<double>(value));
            encoder.encode(vec, scale, destination);
        }, py::arg("values"), py::arg("scale"), py::arg("destination"),
            SEAL_DOC("Encode an iterable of real values into destination."))
        .def("encode", [](CKKSEncoder &encoder, double value, double scale){
            Plaintext pt;
            encoder.encode(value, scale, pt);
            return pt;
        }, py::arg("value"), py::arg("scale"),
            SEAL_DOC("Encode a single real value and return the plaintext."))
        .def("encode", [](CKKSEncoder &encoder, double value, double scale, Plaintext &destination){
            encoder.encode(value, scale, destination);
        }, py::arg("value"), py::arg("scale"), py::arg("destination"),
            SEAL_DOC("Encode a single real value into destination."))
        .def("encode_complex", [](CKKSEncoder &encoder, std::complex<double> value, double scale){
            Plaintext pt;
            encoder.encode(value, scale, pt);
            return pt;
        }, py::arg("value"), py::arg("scale"),
            SEAL_DOC("Encode a single complex value and return the plaintext."))
        .def("encode_complex", [](CKKSEncoder &encoder, std::complex<double> value, double scale, Plaintext &destination){
            encoder.encode(value, scale, destination);
        }, py::arg("value"), py::arg("scale"), py::arg("destination"),
            SEAL_DOC("Encode a single complex value into destination."))
        .def("encode", [](CKKSEncoder &encoder, std::int64_t value){
            Plaintext pt;
            encoder.encode(value, pt);
            return pt;
        }, py::arg("value"),
            SEAL_DOC("Encode a signed integer exactly into a CKKS plaintext."))
        .def("encode", [](CKKSEncoder &encoder, std::int64_t value, Plaintext &destination){
            encoder.encode(value, destination);
        }, py::arg("value"), py::arg("destination"),
            SEAL_DOC("Encode a signed integer exactly into destination."))
        .def("decode", [](CKKSEncoder &encoder, const Plaintext &plain){
            std::vector<double> destination;
            encoder.decode(plain, destination);

            py::array_t<double> values(destination.size());
            py::buffer_info buf = values.request();
            double *ptr = (double *)buf.ptr;

            for (auto i = 0; i < buf.shape[0]; i++)
                ptr[i] = destination[i];

            return values;
        }, py::arg("plain"),
            SEAL_DOC("Decode a CKKS plaintext into a NumPy array of real values."))
        .def("decode_complex", [](CKKSEncoder &encoder, const Plaintext &plain){
            std::vector<std::complex<double>> destination;
            encoder.decode(plain, destination);

            py::array_t<std::complex<double>> values(destination.size());
            py::buffer_info buf = values.request();
            auto *ptr = static_cast<std::complex<double> *>(buf.ptr);

            for (py::ssize_t i = 0; i < buf.shape[0]; i++)
                ptr[i] = destination[static_cast<std::size_t>(i)];

            return values;
        }, py::arg("plain"),
            SEAL_DOC("Decode a CKKS plaintext into a NumPy array of complex values."));

    // decryptor.h
    py::class_<Decryptor>(m, "Decryptor", SEAL_DOC("Decrypts ciphertexts using the secret key and inspects their remaining noise budget."))
        .def(py::init<const SEALContext &, const SecretKey &>(), py::arg("context"), py::arg("secret_key"),
            SEAL_DOC("Create a decryptor for the given context and secret key."))
        .def("decrypt", &Decryptor::decrypt, py::arg("encrypted"), py::arg("destination"),
            SEAL_DOC("Decrypt a ciphertext into destination."))
        .def("invariant_noise_budget", &Decryptor::invariant_noise_budget, py::arg("encrypted"),
            SEAL_DOC("Return the invariant noise budget of a ciphertext in bits."))
        .def("decrypt", [](Decryptor &decryptor, const Ciphertext &encrypted){
            Plaintext pt;
            decryptor.decrypt(encrypted, pt);
            return pt;
        }, py::arg("encrypted"),
            SEAL_DOC("Decrypt a ciphertext and return the plaintext."));

    // batchencoder.h
    py::class_<BatchEncoder>(m, "BatchEncoder", SEAL_DOC("Encodes integer vectors into BFV/BGV batching plaintexts and decodes them back."))
        .def(py::init<const SEALContext &>(), py::arg("context"),
            SEAL_DOC("Create a batch encoder for the given context."))
        .def("slot_count", &BatchEncoder::slot_count, SEAL_DOC("Return the number of batching slots available."))
        .def("encode", [](BatchEncoder &encoder, const std::vector<std::int64_t> &values, Plaintext &destination){
            encoder.encode(values, destination);
        }, py::arg("values"), py::arg("destination"),
            SEAL_DOC("Encode a vector of signed integers into destination."))
        .def("encode", [](BatchEncoder &encoder, const std::vector<std::uint64_t> &values, Plaintext &destination){
            encoder.encode(values, destination);
        }, py::arg("values"), py::arg("destination"),
            SEAL_DOC("Encode a vector of unsigned integers into destination."))
        .def("encode", [](BatchEncoder &encoder, py::array_t<std::int64_t> values){
            py::buffer_info buf = values.request();
            if (buf.ndim != 1)
                throw std::runtime_error("E101: Number of dimensions must be one");

            std::int64_t *ptr = (std::int64_t *)buf.ptr;
            std::vector<std::int64_t> vec(buf.shape[0]);

            for (auto i = 0; i < buf.shape[0]; i++)
                vec[i] = ptr[i];

            Plaintext pt;
            encoder.encode(vec, pt);
            return pt;
        }, py::arg("values"),
            SEAL_DOC("Encode a one-dimensional NumPy array of signed integers and return the plaintext."))
        .def("encode", [](BatchEncoder &encoder, py::array_t<std::uint64_t> values){
            py::buffer_info buf = values.request();
            if (buf.ndim != 1)
                throw std::runtime_error("E101: Number of dimensions must be one");

            auto *ptr = static_cast<std::uint64_t *>(buf.ptr);
            std::vector<std::uint64_t> vec(static_cast<std::size_t>(buf.shape[0]));

            for (py::ssize_t i = 0; i < buf.shape[0]; i++)
                vec[static_cast<std::size_t>(i)] = ptr[i];

            Plaintext pt;
            encoder.encode(vec, pt);
            return pt;
        }, py::arg("values"),
            SEAL_DOC("Encode a one-dimensional NumPy array of unsigned integers and return the plaintext."))
        .def("encode", [](BatchEncoder &encoder, py::iterable values){
            std::vector<std::int64_t> vec;
            vec.reserve(py::len(values));
            for (const auto &value : values)
                vec.push_back(py::cast<std::int64_t>(value));

            Plaintext pt;
            encoder.encode(vec, pt);
            return pt;
        }, py::arg("values"),
            SEAL_DOC("Encode an iterable of integers and return the plaintext."))
        .def("decode_uint64", [](BatchEncoder &encoder, const Plaintext &plain){
            std::vector<std::uint64_t> destination;
            encoder.decode(plain, destination);

            py::array_t<std::uint64_t> values(destination.size());
            py::buffer_info buf = values.request();
            auto *ptr = static_cast<std::uint64_t *>(buf.ptr);

            for (py::ssize_t i = 0; i < buf.shape[0]; i++)
                ptr[i] = destination[static_cast<std::size_t>(i)];

            return values;
        }, py::arg("plain"),
            SEAL_DOC("Decode a batched plaintext into a NumPy array of unsigned 64-bit integers."))
        .def("decode", [](BatchEncoder &encoder, const Plaintext &plain){
            std::vector<std::int64_t> destination;
            encoder.decode(plain, destination);

            py::array_t<std::int64_t> values(destination.size());
            py::buffer_info buf = values.request();
            std::int64_t *ptr = (std::int64_t *)buf.ptr;

            for (auto i = 0; i < buf.shape[0]; i++)
                ptr[i] = destination[i];

            return values;
        }, py::arg("plain"),
            SEAL_DOC("Decode a batched plaintext into a NumPy array of signed 64-bit integers."));
}
