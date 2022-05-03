#include <pybind11/pybind11.h>
#include <pybind11/stl_bind.h>
#include <pybind11/numpy.h>
#include <pybind11/stl.h>
#include "seal/seal.h"
#include <fstream>

using namespace seal;
namespace py = pybind11;

PYBIND11_MAKE_OPAQUE(std::vector<double>);
PYBIND11_MAKE_OPAQUE(std::vector<std::int64_t>);

PYBIND11_MODULE(seal, m)
{
    m.doc() = "Microsoft SEAL for Python, from https://github.com/Huelse/SEAL-Python";
    m.attr("__version__")  = "4.0.0";

    py::bind_vector<std::vector<double>>(m, "VectorDouble", py::buffer_protocol());
    py::bind_vector<std::vector<std::int64_t>>(m, "VectorInt", py::buffer_protocol());

    // encryptionparams.h
    py::enum_<scheme_type>(m, "scheme_type")
        .value("none", scheme_type::none)
        .value("bfv", scheme_type::bfv)
        .value("ckks", scheme_type::ckks)
        .value("bgv", scheme_type::bgv);

    // encryptionparams.h
    py::class_<EncryptionParameters>(m, "EncryptionParameters")
        .def(py::init<scheme_type>())
        .def(py::init<EncryptionParameters>())
        .def("set_poly_modulus_degree", &EncryptionParameters::set_poly_modulus_degree)
        .def("set_coeff_modulus", &EncryptionParameters::set_coeff_modulus)
        .def("set_plain_modulus", py::overload_cast<const Modulus &>(&EncryptionParameters::set_plain_modulus))
        .def("set_plain_modulus", py::overload_cast<std::uint64_t>(&EncryptionParameters::set_plain_modulus))
        .def("scheme", &EncryptionParameters::scheme)
        .def("poly_modulus_degree", &EncryptionParameters::poly_modulus_degree)
        .def("coeff_modulus", &EncryptionParameters::coeff_modulus)
        .def("plain_modulus", &EncryptionParameters::plain_modulus)
        .def("save", [](const EncryptionParameters &parms, std::string &path){
            std::ofstream out(path, std::ofstream::binary);
            parms.save(out);
            out.close();
        })
        .def("load", [](EncryptionParameters &parms, std::string &path){
            std::ifstream in(path, std::ifstream::binary);
            parms.load(in);
            in.close();
        });

    // modulus.h
    py::enum_<sec_level_type>(m, "sec_level_type")
        .value("none", sec_level_type::none)
        .value("tc128", sec_level_type::tc128)
        .value("tc192", sec_level_type::tc192)
        .value("tc256", sec_level_type::tc256);

    // context.h
    py::enum_<EncryptionParameterQualifiers::error_type>(m, "error_type")
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
    py::class_<EncryptionParameterQualifiers, std::unique_ptr<EncryptionParameterQualifiers, py::nodelete>>(m, "EncryptionParameterQualifiers")
        .def("parameters_set", &EncryptionParameterQualifiers::parameters_set)
        .def_readwrite("using_fft", &EncryptionParameterQualifiers::using_fft)
        .def_readwrite("using_ntt", &EncryptionParameterQualifiers::using_ntt)
        .def_readwrite("using_batching", &EncryptionParameterQualifiers::using_batching)
        .def_readwrite("using_fast_plain_lift", &EncryptionParameterQualifiers::using_fast_plain_lift)
        .def_readwrite("using_descending_modulus_chain", &EncryptionParameterQualifiers::using_descending_modulus_chain)
        .def_readwrite("sec_level", &EncryptionParameterQualifiers::sec_level);

    // context.h
    py::class_<SEALContext::ContextData, std::shared_ptr<SEALContext::ContextData>>(m, "ContextData")
        .def("parms", &SEALContext::ContextData::parms)
        .def("parms_id", &SEALContext::ContextData::parms_id)
        .def("qualifiers", &SEALContext::ContextData::qualifiers)
        .def("total_coeff_modulus", &SEALContext::ContextData::total_coeff_modulus)
        .def("total_coeff_modulus_bit_count", &SEALContext::ContextData::total_coeff_modulus_bit_count)
        .def("next_context_data", &SEALContext::ContextData::next_context_data)
        .def("chain_index", &SEALContext::ContextData::chain_index);

    // context.h
    py::class_<SEALContext, std::shared_ptr<SEALContext>>(m, "SEALContext")
        .def(py::init<const EncryptionParameters &, bool, sec_level_type>(), py::arg(), py::arg()=true, py::arg()=sec_level_type::tc128)
        .def("get_context_data", &SEALContext::get_context_data)
        .def("key_context_data", &SEALContext::key_context_data)
        .def("first_context_data", &SEALContext::first_context_data)
        .def("last_context_data", &SEALContext::last_context_data)
        .def("parameters_set", &SEALContext::parameters_set)
        .def("first_parms_id", &SEALContext::first_parms_id)
        .def("last_parms_id", &SEALContext::last_parms_id)
        .def("using_keyswitching", &SEALContext::using_keyswitching);

    // modulus.h
    py::class_<Modulus>(m, "Modulus")
        .def(py::init<std::uint64_t>())
        .def("bit_count", &Modulus::bit_count)
        .def("value", &Modulus::value)
        .def("is_zero", &Modulus::is_zero)
        .def("is_prime", &Modulus::is_prime);
        //save & load

    // modulus.h
    py::class_<CoeffModulus>(m, "CoeffModulus")
        .def_static("MaxBitCount", &CoeffModulus::MaxBitCount, py::arg(), py::arg()=sec_level_type::tc128)
        .def_static("BFVDefault", &CoeffModulus::BFVDefault, py::arg(), py::arg()=sec_level_type::tc128)
        .def_static("Create", py::overload_cast<std::size_t, std::vector<int>>(&CoeffModulus::Create))
        .def_static("Create", py::overload_cast<std::size_t, const Modulus &, std::vector<int>>(&CoeffModulus::Create));

    // modulus.h
    py::class_<PlainModulus>(m, "PlainModulus")
        .def_static("Batching", py::overload_cast<std::size_t, int>(&PlainModulus::Batching))
        .def_static("Batching", py::overload_cast<std::size_t, std::vector<int>>(&PlainModulus::Batching));

    // plaintext.h
    py::class_<Plaintext>(m, "Plaintext")
        .def(py::init<>())
        .def(py::init<std::size_t>())
        .def(py::init<std::size_t, std::size_t>())
        .def(py::init<const std::string &>())
        .def(py::init<const Plaintext &>())
        .def("set_zero", py::overload_cast<std::size_t, std::size_t>(&Plaintext::set_zero))
        .def("set_zero", py::overload_cast<std::size_t>(&Plaintext::set_zero))
        .def("set_zero", py::overload_cast<>(&Plaintext::set_zero))
        .def("is_zero", &Plaintext::is_zero)
        .def("capacity", &Plaintext::capacity)
        .def("coeff_count", &Plaintext::coeff_count)
        .def("significant_coeff_count", &Plaintext::significant_coeff_count)
        .def("nonzero_coeff_count", &Plaintext::nonzero_coeff_count)
        .def("to_string", &Plaintext::to_string)
        .def("is_ntt_form", &Plaintext::is_ntt_form)
        .def("parms_id", py::overload_cast<>(&Plaintext::parms_id, py::const_))
        .def("scale", py::overload_cast<>(&Plaintext::scale, py::const_))
        .def("scale", [](Plaintext &plain, double scale){
            plain.scale() = scale;
        })
        .def("save", [](const Plaintext &plain, const std::string &path){
            std::ofstream out(path, std::ofstream::binary);
            plain.save(out);
            out.close();
        })
        .def("load", [](Plaintext &plain, const SEALContext &context, const std::string &path){
            std::ifstream in(path, std::ifstream::binary);
            plain.load(context, in);
            in.close();
        })
        .def("save_size", [](const Plaintext &plain){
            return plain.save_size();
        });

    // ciphertext.h
    py::class_<Ciphertext>(m, "Ciphertext")
        .def(py::init<>())
        .def(py::init<const SEALContext &>())
        .def(py::init<const SEALContext &, parms_id_type>())
        .def(py::init<const SEALContext &, parms_id_type, std::size_t>())
        .def(py::init<const Ciphertext &>())
        .def("coeff_modulus_size", &Ciphertext::coeff_modulus_size)
        .def("poly_modulus_degree", &Ciphertext::poly_modulus_degree)
        .def("size", &Ciphertext::size)
        .def("size_capacity", &Ciphertext::size_capacity)
        .def("is_transparent", &Ciphertext::is_transparent)
        .def("is_ntt_form", py::overload_cast<>(&Ciphertext::is_ntt_form, py::const_))
        .def("parms_id", py::overload_cast<>(&Ciphertext::parms_id, py::const_))
        .def("scale", py::overload_cast<>(&Ciphertext::scale, py::const_))
        .def("scale", [](Ciphertext &cipher, double scale){
            cipher.scale() = scale;
        })
        .def("save", [](const Ciphertext &cipher, const std::string &path){
            std::ofstream out(path, std::ofstream::binary);
            cipher.save(out);
            out.close();
        })
        .def("load", [](Ciphertext &cipher, const SEALContext &context, const std::string &path){
            std::ifstream in(path, std::ifstream::binary);
            cipher.load(context, in);
            in.close();
        })
        .def("save_size", [](const Ciphertext &cipher){
            return cipher.save_size();
        });

    // secretkey.h
    py::class_<SecretKey>(m, "SecretKey")
        .def(py::init<>())
        .def(py::init<const SecretKey &>())
        .def("parms_id", py::overload_cast<>(&SecretKey::parms_id, py::const_))
        .def("save", [](const SecretKey &sk, const std::string &path){
            std::ofstream out(path, std::ofstream::binary);
            sk.save(out);
            out.close();
        })
        .def("load", [](SecretKey &sk, const SEALContext &context, const std::string &path){
            std::ifstream in(path, std::ifstream::binary);
            sk.load(context, in);
            in.close();
        });

    // publickey.h
    py::class_<PublicKey>(m, "PublicKey")
        .def(py::init<>())
        .def(py::init<const PublicKey &>())
        .def("parms_id", py::overload_cast<>(&PublicKey::parms_id, py::const_))
        .def("save", [](const PublicKey &pk, const std::string &path){
            std::ofstream out(path, std::ofstream::binary);
            pk.save(out);
            out.close();
        })
        .def("load", [](PublicKey &pk, const SEALContext &context, const std::string &path){
            std::ifstream in(path, std::ifstream::binary);
            pk.load(context, in);
            in.close();
        });

    // kswitchkeys.h
    py::class_<KSwitchKeys>(m, "KSwitchKeys")
        .def(py::init<>())
        .def(py::init<const KSwitchKeys &>())
        .def("size", &KSwitchKeys::size)
        .def("parms_id", py::overload_cast<>(&KSwitchKeys::parms_id, py::const_))
        .def("save", [](const KSwitchKeys &ksk, const std::string &path){
            std::ofstream out(path, std::ofstream::binary);
            ksk.save(out);
            out.close();
        })
        .def("load", [](KSwitchKeys &ksk, const SEALContext &context, const std::string &path){
            std::ifstream in(path, std::ifstream::binary);
            ksk.load(context, in);
            in.close();
        });

    // relinKeys.h
    py::class_<RelinKeys, KSwitchKeys>(m, "RelinKeys")
        .def(py::init<>())
        .def(py::init<const RelinKeys::KSwitchKeys &>())
        .def("size", &RelinKeys::KSwitchKeys::size)
        .def("parms_id", py::overload_cast<>(&RelinKeys::KSwitchKeys::parms_id, py::const_))
        .def_static("get_index", &RelinKeys::get_index)
        .def("has_key", &RelinKeys::has_key)
        .def("save", [](const RelinKeys &rk, const std::string &path){
            std::ofstream out(path, std::ofstream::binary);
            rk.save(out);
            out.close();
        })
        .def("load", [](RelinKeys &rk, const SEALContext &context, const std::string &path){
            std::ifstream in(path, std::ifstream::binary);
            rk.load(context, in);
            in.close();
        });

    // galoisKeys.h
    py::class_<GaloisKeys, KSwitchKeys>(m, "GaloisKeys")
        .def(py::init<>())
        .def(py::init<const GaloisKeys::KSwitchKeys &>())
        .def("size", &GaloisKeys::KSwitchKeys::size)
        .def("parms_id", py::overload_cast<>(&GaloisKeys::KSwitchKeys::parms_id, py::const_))
        .def_static("get_index", &GaloisKeys::get_index)
        .def("has_key", &GaloisKeys::has_key)
        .def("save", [](const GaloisKeys &gk, const std::string &path){
            std::ofstream out(path, std::ofstream::binary);
            gk.save(out);
            out.close();
        })
        .def("load", [](GaloisKeys &gk, const SEALContext &context, const std::string &path){
            std::ifstream in(path, std::ifstream::binary);
            gk.load(context, in);
            in.close();
        });

    // keygenerator.h
    py::class_<KeyGenerator>(m, "KeyGenerator")
        .def(py::init<const SEALContext &>())
        .def(py::init<const SEALContext &, const SecretKey &>())
        .def("secret_key", &KeyGenerator::secret_key)
        .def("create_public_key", py::overload_cast<PublicKey &>(&KeyGenerator::create_public_key, py::const_))
        .def("create_relin_keys", py::overload_cast<RelinKeys &>(&KeyGenerator::create_relin_keys))
        .def("create_galois_keys", py::overload_cast<const std::vector<int> &, GaloisKeys &>(&KeyGenerator::create_galois_keys))
        .def("create_galois_keys", py::overload_cast<GaloisKeys &>(&KeyGenerator::create_galois_keys))
        .def("create_public_key", [](KeyGenerator &keygen){
            PublicKey pk;
            keygen.create_public_key(pk);
            return pk;
        })
        .def("create_relin_keys", [](KeyGenerator &keygen){
            RelinKeys rk;
            keygen.create_relin_keys(rk);
            return rk;
        })
        .def("create_galois_keys", [](KeyGenerator &keygen){
            GaloisKeys gk;
            keygen.create_galois_keys(gk);
            return gk;
        });

    // encryptor.h
    py::class_<Encryptor>(m, "Encryptor")
        .def(py::init<const SEALContext &, const PublicKey &>())
        .def(py::init<const SEALContext &, const SecretKey &>())
        .def(py::init<const SEALContext &, const PublicKey &, const SecretKey &>())
        .def("set_public_key", &Encryptor::set_public_key)
        .def("set_secret_key", &Encryptor::set_secret_key)
        .def("encrypt_zero", [](const Encryptor &encryptor){
            Ciphertext encrypted;
            encryptor.encrypt_zero(encrypted);
            return encrypted;
        })
        .def("encrypt", [](const Encryptor &encryptor, const Plaintext &plain){
            Ciphertext encrypted;
            encryptor.encrypt(plain, encrypted);
            return encrypted;
        });
        // symmetric

    // evaluator.h
    py::class_<Evaluator>(m, "Evaluator")
        .def(py::init<const SEALContext &>())
        .def("negate_inplace", &Evaluator::negate_inplace)
        .def("negate", [](Evaluator &evaluator, const Ciphertext &encrypted1){
            Ciphertext destination;
            evaluator.negate(encrypted1, destination);
            return destination;
        })
        .def("add_inplace", &Evaluator::add_inplace)
        .def("add", [](Evaluator &evaluator, const Ciphertext &encrypted1, const Ciphertext &encrypted2){
            Ciphertext destination;
            evaluator.add(encrypted1, encrypted2, destination);
            return destination;
        })
        .def("add_many", [](Evaluator &evaluator, const std::vector<Ciphertext> &encrypteds){
            Ciphertext destination;
            evaluator.add_many(encrypteds, destination);
            return destination;
        })
        .def("sub_inplace", &Evaluator::sub_inplace)
        .def("sub", [](Evaluator &evaluator, const Ciphertext &encrypted1, const Ciphertext &encrypted2){
            Ciphertext destination;
            evaluator.sub(encrypted1, encrypted2, destination);
            return destination;
        })
        .def("multiply_inplace", [](Evaluator &evaluator, Ciphertext &encrypted1, const Ciphertext &encrypted2){
            evaluator.multiply_inplace(encrypted1, encrypted2);
        })
        .def("multiply", [](Evaluator &evaluator, const Ciphertext &encrypted1, const Ciphertext &encrypted2){
            Ciphertext destination;
            evaluator.multiply(encrypted1, encrypted2, destination);
            return destination;
        })
        .def("square_inplace", [](Evaluator &evaluator, Ciphertext &encrypted1){
            evaluator.square_inplace(encrypted1);
        })
        .def("square", [](Evaluator &evaluator, const Ciphertext &encrypted1){
            Ciphertext destination;
            evaluator.square(encrypted1, destination);
            return destination;
        })
        .def("relinearize_inplace", [](Evaluator &evaluator, Ciphertext &encrypted1, const RelinKeys &relin_keys){
            evaluator.relinearize_inplace(encrypted1, relin_keys);
        })
        .def("relinearize", [](Evaluator &evaluator, const Ciphertext &encrypted1, const RelinKeys &relin_keys){
            Ciphertext destination;
            evaluator.relinearize(encrypted1, relin_keys, destination);
            return destination;
        })
        .def("mod_switch_to_next", [](Evaluator &evaluator, const Ciphertext &encrypted){
            Ciphertext destination;
            evaluator.mod_switch_to_next(encrypted, destination);
            return destination;
        })
        .def("mod_switch_to_next_inplace", [](Evaluator &evaluator, Ciphertext &encrypted){
            evaluator.mod_switch_to_next_inplace(encrypted);
        })
        .def("mod_switch_to_next_inplace", py::overload_cast<Plaintext &>(&Evaluator::mod_switch_to_next_inplace, py::const_))
        .def("mod_switch_to_next", [](Evaluator &evaluator, const Plaintext &plain){
            Plaintext destination;
            evaluator.mod_switch_to_next(plain, destination);
            return destination;
        })
        .def("mod_switch_to_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, parms_id_type parms_id){
            evaluator.mod_switch_to_inplace(encrypted, parms_id);
        })
        .def("mod_switch_to", [](Evaluator &evaluator, const Ciphertext &encrypted, parms_id_type parms_id){
            Ciphertext destination;
            evaluator.mod_switch_to(encrypted, parms_id, destination);
            return destination;
        })
        .def("mod_switch_to_inplace", py::overload_cast<Plaintext &, parms_id_type>(&Evaluator::mod_switch_to_inplace, py::const_))
        .def("mod_switch_to", [](Evaluator &evaluator, const Plaintext &plain, parms_id_type parms_id){
            Plaintext destination;
            evaluator.mod_switch_to(plain, parms_id, destination);
            return destination;
        })
        .def("rescale_to_next", [](Evaluator &evaluator, const Ciphertext &encrypted){
            Ciphertext destination;
            evaluator.rescale_to_next(encrypted, destination);
            return destination;
        })
        .def("rescale_to_next_inplace", [](Evaluator &evaluator, Ciphertext &encrypted){
            evaluator.rescale_to_next_inplace(encrypted);
        })
        .def("rescale_to_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, parms_id_type parms_id){
            evaluator.rescale_to_inplace(encrypted, parms_id);
        })
        .def("rescale_to", [](Evaluator &evaluator, const Ciphertext &encrypted, parms_id_type parms_id){
            Ciphertext destination;
            evaluator.rescale_to(encrypted, parms_id, destination);
            return destination;
        })
        .def("multiply_many", [](Evaluator &evaluator,  const std::vector<Ciphertext> &encrypteds, const RelinKeys &relin_keys){
            Ciphertext destination;
            evaluator.multiply_many(encrypteds, relin_keys, destination);
            return destination;
        })
        .def("exponentiate_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, std::uint64_t exponent, const RelinKeys &relin_keys){
            evaluator.exponentiate_inplace(encrypted, exponent, relin_keys);
        })
        .def("exponentiate", [](Evaluator &evaluator,  const Ciphertext &encrypted, std::uint64_t exponent, const RelinKeys &relin_keys){
            Ciphertext destination;
            evaluator.exponentiate(encrypted, exponent, relin_keys, destination);
            return destination;
        })
        .def("add_plain_inplace", &Evaluator::add_plain_inplace)
        .def("add_plain", [](Evaluator &evaluator, const Ciphertext &encrypted, const Plaintext &plain){
            Ciphertext destination;
            evaluator.add_plain(encrypted, plain, destination);
            return destination;
        })
        .def("sub_plain_inplace", &Evaluator::sub_plain_inplace)
        .def("sub_plain", [](Evaluator &evaluator, const Ciphertext &encrypted, const Plaintext &plain){
            Ciphertext destination;
            evaluator.sub_plain(encrypted, plain, destination);
            return destination;
        })
        .def("multiply_plain_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, const Plaintext &plain){
            evaluator.multiply_plain_inplace(encrypted, plain);
        })
        .def("multiply_plain", [](Evaluator &evaluator, const Ciphertext &encrypted, const Plaintext &plain){
            Ciphertext destination;
            evaluator.multiply_plain(encrypted, plain, destination);
            return destination;
        })
        .def("transform_to_ntt_inplace", [](Evaluator &evaluator, Plaintext &plain, parms_id_type parms_id){
            evaluator.transform_to_ntt_inplace(plain,parms_id);
        })
        .def("transform_to_ntt", [](Evaluator &evaluator, const Plaintext &plain, parms_id_type parms_id){
            Plaintext destination_ntt;
            evaluator.transform_to_ntt(plain, parms_id, destination_ntt);
            return destination_ntt;
        })
        .def("transform_to_ntt_inplace", py::overload_cast<Ciphertext &>(&Evaluator::transform_to_ntt_inplace, py::const_))
        .def("transform_to_ntt", [](Evaluator &evaluator, const Ciphertext &encrypted){
            Ciphertext destination_ntt;
            evaluator.transform_to_ntt(encrypted, destination_ntt);
            return destination_ntt;
        })
        .def("transform_from_ntt_inplace", &Evaluator::transform_from_ntt_inplace)
        .def("transform_from_ntt", [](Evaluator &evaluator, const Ciphertext &encrypted_ntt){
            Ciphertext destination;
            evaluator.transform_from_ntt(encrypted_ntt, destination);
            return destination;
        })
        .def("apply_galois_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, std::uint32_t galois_elt, const GaloisKeys &galois_keys){
            evaluator.apply_galois_inplace(encrypted, galois_elt, galois_keys);
        })
        .def("apply_galois", [](Evaluator &evaluator, const Ciphertext &encrypted, std::uint32_t galois_elt, const GaloisKeys &galois_keys){
            Ciphertext destination;
            evaluator.apply_galois(encrypted, galois_elt, galois_keys, destination);
            return destination;
        })
        .def("rotate_rows_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys){
            evaluator.rotate_rows_inplace(encrypted, steps, galois_keys);
        })
        .def("rotate_rows", [](Evaluator &evaluator, const Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys){
            Ciphertext destination;
            evaluator.rotate_rows(encrypted, steps, galois_keys, destination);
            return destination;
        })
        .def("rotate_columns_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, const GaloisKeys &galois_keys){
            evaluator.rotate_columns_inplace(encrypted, galois_keys);
        })
        .def("rotate_columns", [](Evaluator &evaluator, const Ciphertext &encrypted, const GaloisKeys &galois_keys){
            Ciphertext destination;
            evaluator.rotate_columns(encrypted, galois_keys, destination);
            return destination;
        })
        .def("rotate_vector_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys){
            evaluator.rotate_vector_inplace(encrypted, steps, galois_keys);
        })
        .def("rotate_vector", [](Evaluator &evaluator, const Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys){
            Ciphertext destination;
            evaluator.rotate_vector(encrypted, steps, galois_keys, destination);
            return destination;
        })
        .def("complex_conjugate_inplace", [](Evaluator &evaluator, Ciphertext &encrypted, const GaloisKeys &galois_keys){
            evaluator.complex_conjugate_inplace(encrypted, galois_keys);
        })
        .def("complex_conjugate", [](Evaluator &evaluator, const Ciphertext &encrypted, const GaloisKeys &galois_keys){
            Ciphertext destination;
            evaluator.complex_conjugate(encrypted, galois_keys, destination);
            return destination;
        });

    // ckks.h
    py::class_<CKKSEncoder>(m, "CKKSEncoder")
        .def(py::init<const SEALContext &>())
        .def("slot_count", &CKKSEncoder::slot_count)
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
        })
        .def("encode", [](CKKSEncoder &encoder, double value, double scale){
            Plaintext pt;
            encoder.encode(value, scale, pt);
            return pt;
        })
        .def("decode", [](CKKSEncoder &encoder, const Plaintext &plain){
            std::vector<double> destination;
            encoder.decode(plain, destination);

            py::array_t<double> values(destination.size());
            py::buffer_info buf = values.request();
            double *ptr = (double *)buf.ptr;

            for (auto i = 0; i < buf.shape[0]; i++)
                ptr[i] = destination[i];

            return values;
        });

    // decryptor.h
    py::class_<Decryptor>(m, "Decryptor")
        .def(py::init<const SEALContext &, const SecretKey &>())
        .def("decrypt", &Decryptor::decrypt)
        .def("invariant_noise_budget", &Decryptor::invariant_noise_budget)
        .def("decrypt", [](Decryptor &decryptor, const Ciphertext &encrypted){
            Plaintext pt;
            decryptor.decrypt(encrypted, pt);
            return pt;
        });

    // batchencoder.h
    py::class_<BatchEncoder>(m, "BatchEncoder")
        .def(py::init<const SEALContext &>())
        .def("slot_count", &BatchEncoder::slot_count)
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
        })
        .def("decode", [](BatchEncoder &encoder, const Plaintext &plain){
            std::vector<std::int64_t> destination;
            encoder.decode(plain, destination);

            py::array_t<std::int64_t> values(destination.size());
            py::buffer_info buf = values.request();
            std::int64_t *ptr = (std::int64_t *)buf.ptr;

            for (auto i = 0; i < buf.shape[0]; i++)
                ptr[i] = destination[i];

            return values;
        });
}
