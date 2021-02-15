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
    m.doc() = "Microsoft SEAL (3.6.1) for Python, from https://github.com/Huelse/SEAL-Python";
    
    py::bind_vector<std::vector<double>>(m, "VectorDouble", py::buffer_protocol());
    py::bind_vector<std::vector<std::int64_t>>(m, "VectorInt", py::buffer_protocol());

    // encryptionparams.h
    py::enum_<scheme_type>(m, "scheme_type")
        .value("none", scheme_type::none)
        .value("bfv", scheme_type::bfv)
        .value("ckks", scheme_type::ckks);
    
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
        .def("save", [](const EncryptionParameters &ep, std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			ep.save(out);
			out.close();
		})
		.def("load", [](EncryptionParameters &ep, std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			ep.load(in);
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
		.def_static("Create", &CoeffModulus::Create);

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
		.def("save", [](const Plaintext &pt, const std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			pt.save(out);
			out.close();
		})
		.def("load", [](Plaintext &pt, const SEALContext &context, const std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			pt.load(context, in);
			in.close();
		})
		.def("is_ntt_form", &Plaintext::is_ntt_form)
		.def("parms_id", py::overload_cast<>(&Plaintext::parms_id, py::const_), py::return_value_policy::reference)
		.def("scale", py::overload_cast<>(&Plaintext::scale, py::const_), py::return_value_policy::reference)
		.def("scale", [](Plaintext &pt, double scale) {
			pt.scale() = scale;
		});;

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
		.def("save", [](const Ciphertext &ct, const std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			ct.save(out);
			out.close();
		})
		.def("load", [](Ciphertext &ct, const SEALContext &context, const std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			ct.load(context, in);
			in.close();
		})
		.def("is_ntt_form", py::overload_cast<>(&Ciphertext::is_ntt_form, py::const_))
		.def("parms_id", py::overload_cast<>(&Ciphertext::parms_id, py::const_), py::return_value_policy::reference)
		.def("scale", py::overload_cast<>(&Ciphertext::scale, py::const_), py::return_value_policy::reference)
		.def("scale", [](Ciphertext &ct, double scale) {
			ct.scale() = scale;
		});

	// secretkey.h
	py::class_<SecretKey>(m, "SecretKey")
		.def(py::init<>())
		.def(py::init<const SecretKey &>())
		.def("parms_id", py::overload_cast<>(&SecretKey::parms_id, py::const_), py::return_value_policy::reference)
		.def("save", [](const SecretKey &sk, const std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			sk.save(out);
			out.close();
		})
		.def("load", [](SecretKey &sk, const SEALContext &context, const std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			sk.load(context, in);
			in.close();
		});
	
	// publickey.h
	py::class_<PublicKey>(m, "PublicKey")
		.def(py::init<>())
		.def(py::init<const PublicKey &>())
		.def("parms_id", py::overload_cast<>(&PublicKey::parms_id, py::const_), py::return_value_policy::reference)
		.def("save", [](const PublicKey &pk, const std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			pk.save(out);
			out.close();
		})
		.def("load", [](PublicKey &pk, const SEALContext &context, const std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			pk.load(context, in);
			in.close();
		});

	// kswitchkeys.h
	py::class_<KSwitchKeys>(m, "KSwitchKeys")
		.def(py::init<>())
		.def(py::init<const KSwitchKeys &>())
		.def("size", &KSwitchKeys::size)
		.def("parms_id", py::overload_cast<>(&KSwitchKeys::parms_id, py::const_), py::return_value_policy::reference)
		.def("save", [](const KSwitchKeys &ksk, const std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			ksk.save(out);
			out.close();
		})
		.def("load", [](KSwitchKeys &ksk, const SEALContext &context, const std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			ksk.load(context, in);
			in.close();
		});

	// relinKeys.h
	py::class_<RelinKeys, KSwitchKeys>(m, "RelinKeys")
		.def(py::init<>())
		.def(py::init<const RelinKeys::KSwitchKeys &>())
		.def("size", &RelinKeys::KSwitchKeys::size)
		.def("parms_id", py::overload_cast<>(&RelinKeys::KSwitchKeys::parms_id, py::const_), py::return_value_policy::reference)
		.def("save", [](const RelinKeys &rk, const std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			rk.save(out);
			out.close();
		})
		.def("load", [](RelinKeys &rk, const SEALContext &context, const std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			rk.load(context, in);
			in.close();
		})
		.def_static("get_index", &RelinKeys::get_index)
		.def("has_key", &RelinKeys::has_key);

	// galoisKeys.h
	py::class_<GaloisKeys, KSwitchKeys>(m, "GaloisKeys")
		.def(py::init<>())
		.def(py::init<const GaloisKeys::KSwitchKeys &>())
		.def("size", &GaloisKeys::KSwitchKeys::size)
		.def("parms_id", py::overload_cast<>(&GaloisKeys::KSwitchKeys::parms_id, py::const_), py::return_value_policy::reference)
		.def("save", [](const GaloisKeys &gk, const std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			gk.save(out);
			out.close();
		})
		.def("load", [](GaloisKeys &gk, const SEALContext &context, const std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			gk.load(context, in);
			in.close();
		})
		.def_static("get_index", &GaloisKeys::get_index)
		.def("has_key", &GaloisKeys::has_key);

	// keygenerator.h
	py::class_<KeyGenerator>(m, "KeyGenerator")
		.def(py::init<const SEALContext &>())
		.def(py::init<const SEALContext &, const SecretKey &>())
		.def("secret_key", &KeyGenerator::secret_key, py::return_value_policy::reference)
		.def("create_public_key", py::overload_cast<PublicKey &>(&KeyGenerator::create_public_key, py::const_))
		.def("create_relin_keys", py::overload_cast<RelinKeys &>(&KeyGenerator::create_relin_keys))
		.def("create_galois_keys", py::overload_cast<const std::vector<int> &, GaloisKeys &>(&KeyGenerator::create_galois_keys))
		.def("create_galois_keys", py::overload_cast<GaloisKeys &>(&KeyGenerator::create_galois_keys))
		.def("create_public_key", [](const KeyGenerator &keygen){
			PublicKey pk;
			keygen.create_public_key(pk);
			return pk;
		});

	// encryptor.h
	py::class_<Encryptor>(m, "Encryptor")
		.def(py::init<const SEALContext &, const PublicKey &>())
		.def(py::init<const SEALContext &, const SecretKey &>())
		.def(py::init<const SEALContext &, const PublicKey &, const SecretKey &>())
		.def("set_public_key", &Encryptor::set_public_key)
		.def("set_secret_key", &Encryptor::set_secret_key)
		.def("encrypt_zero", [](const Encryptor &encryptor){
			Ciphertext ct;
			encryptor.encrypt_zero(ct);
			return ct;
		})
		.def("encrypt", [](const Encryptor &encryptor, const Plaintext &pt){
			Ciphertext ct;
			encryptor.encrypt(pt, ct);
			return ct;
		});
		// symmetric

	// evaluator.h
	py::class_<Evaluator>(m, "Evaluator")
		.def(py::init<const SEALContext &>())
		.def("negate_inplace", &Evaluator::negate_inplace)
		.def("negate", &Evaluator::negate)
		.def("add_inplace", &Evaluator::add_inplace)
		.def("add", &Evaluator::add)
		.def("add_many", &Evaluator::add_many)
		.def("sub_inplace", &Evaluator::sub_inplace)
		.def("sub", &Evaluator::sub)
		.def("multiply_inplace", &Evaluator::multiply_inplace)
		.def("multiply", &Evaluator::multiply)
		.def("square_inplace", &Evaluator::square_inplace)
		.def("square", &Evaluator::square)
		.def("relinearize_inplace", &Evaluator::relinearize_inplace)
		.def("relinearize", &Evaluator::relinearize)
		;

	// ckks.h
	py::class_<CKKSEncoder>(m, "CKKSEncoder")
		.def(py::init<const SEALContext &>())
		.def("slot_count", &CKKSEncoder::slot_count)
		.def("encode", [](CKKSEncoder &encoder, py::array_t<double> values, double scale){
			py::buffer_info buf = values.request();
			if (buf.ndim != 1)
				throw std::runtime_error("Number of dimensions must be one");

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
		.def("decrypt", [](Decryptor &decryptor, const Ciphertext &ct){
			Plaintext pt;
			decryptor.decrypt(ct, pt);
			return pt;
		});

	// batchencoder.h
	py::class_<BatchEncoder>(m, "BatchEncoder")
		.def(py::init<const SEALContext &>())
		.def("encode", [](BatchEncoder &encoder, py::array_t<std::int64_t> values){
			py::buffer_info buf = values.request();
			if (buf.ndim != 1)
				throw std::runtime_error("Number of dimensions must be one");

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
