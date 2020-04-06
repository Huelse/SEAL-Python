#include <pybind11/pybind11.h>
#include <pybind11/stl_bind.h>
#include <pybind11/complex.h>
#include <pybind11/numpy.h>
#include <pybind11/stl.h>
#include "seal/seal.h"
#include <fstream>

using namespace std;
using namespace seal;

namespace py = pybind11;

PYBIND11_MAKE_OPAQUE(std::vector<double>);
PYBIND11_MAKE_OPAQUE(std::vector<std::complex<double>>);
PYBIND11_MAKE_OPAQUE(std::vector<std::uint64_t>);
PYBIND11_MAKE_OPAQUE(std::vector<std::int64_t>);

using parms_id_type = std::array<std::uint64_t, 4>;

PYBIND11_MODULE(seal, m)
{
	m.doc() = "Microsoft SEAL (3.4.5) For Python. From https://github.com/Huelse/SEAL-Python";

	py::bind_vector<std::vector<double>>(m, "DoubleVector", py::buffer_protocol());
	py::bind_vector<std::vector<std::complex<double>>>(m, "ComplexDoubleVector", py::buffer_protocol());
	py::bind_vector<std::vector<std::uint64_t>>(m, "uIntVector", py::buffer_protocol());
	py::bind_vector<std::vector<std::int64_t>>(m, "IntVector", py::buffer_protocol());

	// encryptionparams.h
	py::enum_<scheme_type>(m, "scheme_type", py::arithmetic())
		.value("none", scheme_type::none)
		.value("BFV", scheme_type::BFV)
		.value("CKKS", scheme_type::CKKS);

	// modulus.h
	py::enum_<sec_level_type>(m, "sec_level_type", py::arithmetic())
		.value("none", sec_level_type::none)
		.value("tc128", sec_level_type::tc128)
		.value("tc192", sec_level_type::tc192)
		.value("tc256", sec_level_type::tc256);

	// encryptionparams.h
	py::class_<EncryptionParameters>(m, "EncryptionParameters")
		.def(py::init<scheme_type>())
		.def(py::init<std::uint8_t>())
		.def("set_poly_modulus_degree", &EncryptionParameters::set_poly_modulus_degree)
		.def("set_coeff_modulus", &EncryptionParameters::set_coeff_modulus)
		.def("set_plain_modulus", (void (EncryptionParameters::*)(const SmallModulus &)) & EncryptionParameters::set_plain_modulus)
		.def("set_plain_modulus", (void (EncryptionParameters::*)(std::uint64_t)) & EncryptionParameters::set_plain_modulus)
		.def("scheme", &EncryptionParameters::scheme)
		.def("poly_modulus_degree", &EncryptionParameters::poly_modulus_degree)
		.def("coeff_modulus", &EncryptionParameters::coeff_modulus)
		.def("plain_modulus", &EncryptionParameters::plain_modulus)
		.def("save", [](const EncryptionParameters &p, std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			p.save(out);
			out.close();
		})
		.def("load", [](EncryptionParameters &p, std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			p.load(in);
			in.close();
		});

	// context.h
	py::class_<EncryptionParameterQualifiers, std::unique_ptr<EncryptionParameterQualifiers, py::nodelete>>(m, "EncryptionParameterQualifiers")
		.def_readwrite("parameters_set", &EncryptionParameterQualifiers::parameters_set)
		.def_readwrite("using_fft", &EncryptionParameterQualifiers::using_fft)
		.def_readwrite("using_ntt", &EncryptionParameterQualifiers::using_ntt)
		.def_readwrite("using_batching", &EncryptionParameterQualifiers::using_batching)
		.def_readwrite("using_fast_plain_lift", &EncryptionParameterQualifiers::using_fast_plain_lift)
		.def_readwrite("using_descending_modulus_chain", &EncryptionParameterQualifiers::using_descending_modulus_chain)
		.def_readwrite("sec_level", &EncryptionParameterQualifiers::sec_level);

	// context.h
	py::class_<SEALContext, std::shared_ptr<SEALContext>>(m, "SEALContext")
		// .def_static("Create", [](const EncryptionParameters &parms) { return SEALContext::Create(parms); })
		.def_static("Create", &SEALContext::Create, py::arg(), py::arg() = true, py::arg() = sec_level_type::tc128)
		.def("get_context_data", &SEALContext::get_context_data)
		.def("key_context_data", &SEALContext::key_context_data)
		.def("first_context_data", &SEALContext::first_context_data)
		.def("first_parms_id", &SEALContext::first_parms_id)
		.def("last_parms_id", &SEALContext::last_parms_id)
		.def("using_keyswitching", &SEALContext::using_keyswitching);

	// context.h
	py::class_<SEALContext::ContextData, std::shared_ptr<SEALContext::ContextData>>(m, "SEALContext::ContextData")
		.def("parms", &SEALContext::ContextData::parms)
		.def("parms_id", &SEALContext::ContextData::parms_id)
		.def("qualifiers", &SEALContext::ContextData::qualifiers)
		.def("total_coeff_modulus", &SEALContext::ContextData::total_coeff_modulus)
		.def("total_coeff_modulus_bit_count", &SEALContext::ContextData::total_coeff_modulus_bit_count)
		.def("next_context_data", &SEALContext::ContextData::next_context_data)
		.def("chain_index", &SEALContext::ContextData::chain_index);

	// memorymanager.h
	py::class_<MemoryPoolHandle>(m, "MemoryPoolHandle")
		.def(py::init<>());

	// memorymanager.h
	py::class_<MemoryManager>(m, "MemoryManager")
		.def_static("GetPool", []() { return MemoryManager::GetPool(); });

	// smallmodulus.h
	py::class_<SmallModulus>(m, "SmallModulus")
		.def(py::init<>())
		.def(py::init<std::uint64_t>())
		.def("bit_count", &SmallModulus::bit_count)
		.def("value", &SmallModulus::value);

	// modulus.h
	py::class_<CoeffModulus>(m, "CoeffModulus")
		.def_static("BFVDefault", [](std::size_t poly_modulus_degree) { return CoeffModulus::BFVDefault(poly_modulus_degree); })
		.def_static("Create", [](std::size_t poly_modulus_degree, std::vector<int> bit_sizes) { return CoeffModulus::Create(poly_modulus_degree, bit_sizes); })
		.def_static("MaxBitCount", [](std::size_t poly_modulus_degree) { return CoeffModulus::MaxBitCount(poly_modulus_degree); });

	// modulus.h
	py::class_<PlainModulus>(m, "PlainModulus")
		.def("Batching", [](std::size_t poly_modulus_degree, int bit_size) { return PlainModulus::Batching(poly_modulus_degree, bit_size); })
		.def("Batching", [](std::size_t poly_modulus_degree, std::vector<int> bit_sizes) { return PlainModulus::Batching(poly_modulus_degree, bit_sizes); });

	// plaintext.h
	py::class_<Plaintext>(m, "Plaintext")
		.def(py::init<MemoryPoolHandle>(), py::arg() = MemoryManager::GetPool())
		.def(py::init<std::size_t, MemoryPoolHandle>(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def(py::init<std::size_t, std::size_t, MemoryPoolHandle>(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def(py::init<const std::string &, MemoryPoolHandle>(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def(py::init<const Plaintext &>())
		.def("reserve", &Plaintext::reserve)
		.def("release", &Plaintext::release)
		.def("resize", &Plaintext::resize)
		.def("set_zero", (void (Plaintext::*)(std::size_t, std::size_t)) & Plaintext::set_zero)
		.def("set_zero", (void (Plaintext::*)(std::size_t)) & Plaintext::set_zero)
		.def("set_zero", (void (Plaintext::*)()) & Plaintext::set_zero)
		.def("coeff_count", &Plaintext::coeff_count)
		.def("significant_coeff_count", &Plaintext::significant_coeff_count)
		.def("to_string", &Plaintext::to_string)
		.def("parms_id", (parms_id_type & (Plaintext::*)()) & Plaintext::parms_id, py::return_value_policy::reference)
		.def("scale", (double &(Plaintext::*)()) & Plaintext::scale, py::return_value_policy::reference)
		.def("save", [](const Plaintext &c, std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			c.save(out);
			out.close();
		})
		.def("load", [](Plaintext &c, std::shared_ptr<SEALContext> &context, std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			c.load(context, in);
			in.close();
		});

	// ciphertext.h
	py::class_<Ciphertext>(m, "Ciphertext")
		.def(py::init<>())
		.def(py::init<std::shared_ptr<SEALContext>>())
		.def(py::init<std::shared_ptr<SEALContext>, parms_id_type>())
		.def(py::init<std::shared_ptr<SEALContext>, parms_id_type, std::size_t>())
		.def(py::init<const Ciphertext &>())
		.def("reserve", (void (Ciphertext::*)(std::shared_ptr<SEALContext>, parms_id_type, std::size_t)) & Ciphertext::reserve)
		.def("reserve", (void (Ciphertext::*)(std::shared_ptr<SEALContext>, std::size_t)) & Ciphertext::reserve)
		.def("reserve", (void (Ciphertext::*)(std::size_t)) & Ciphertext::reserve)
		.def("resize", (void (Ciphertext::*)(std::shared_ptr<SEALContext>, std::size_t)) & Ciphertext::resize)
		.def("resize", (void (Ciphertext::*)(std::size_t)) & Ciphertext::resize)
		.def("release", &Ciphertext::release)
		.def("size", &Ciphertext::size)
		.def("parms_id", (parms_id_type & (Ciphertext::*)()) & Ciphertext::parms_id, py::return_value_policy::reference)
		.def("scale", (double &(Ciphertext::*)()) & Ciphertext::scale, py::return_value_policy::reference)
		.def("scale", [](Ciphertext &c, double scale) {
			c.scale() = scale;
		})
		.def("save", [](const Ciphertext &c, std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			c.save(out);
			out.close();
		})
		.def("load", [](Ciphertext &c, std::shared_ptr<SEALContext> &context, std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			c.load(context, in);
			in.close();
		});

	// secretkey.h
	py::class_<SecretKey>(m, "SecretKey")
		.def(py::init<>())
		.def("parms_id", (parms_id_type & (SecretKey::*)()) & SecretKey::parms_id, py::return_value_policy::reference)
		.def("save", [](const SecretKey &c, std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			c.save(out);
			out.close();
		})
		.def("load", [](SecretKey &c, std::shared_ptr<SEALContext> &context, std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			c.load(context, in);
			in.close();
		});

	// publickey.h
	py::class_<PublicKey>(m, "PublicKey")
		.def(py::init<>())
		.def("parms_id", (parms_id_type & (PublicKey::*)()) & PublicKey::parms_id, py::return_value_policy::reference)
		.def("save", [](const PublicKey &c, std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			c.save(out);
			out.close();
		})
		.def("load", [](PublicKey &c, std::shared_ptr<SEALContext> &context, std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			c.load(context, in);
			in.close();
		});

	// kswitchkeys.h
	py::class_<KSwitchKeys>(m, "KSwitchKeys")
		.def(py::init<>())
		.def("parms_id", (parms_id_type & (KSwitchKeys::*)()) & KSwitchKeys::parms_id, py::return_value_policy::reference)
		.def("save", [](const KSwitchKeys &c, std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			c.save(out);
			out.close();
		})
		.def("load", [](KSwitchKeys &c, std::shared_ptr<SEALContext> &context, std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			c.load(context, in);
			in.close();
		});

	// relinKeys.h
	py::class_<RelinKeys, KSwitchKeys>(m, "RelinKeys")
		.def(py::init<>())
		.def("parms_id", (parms_id_type & (RelinKeys::KSwitchKeys::*)()) & RelinKeys::KSwitchKeys::parms_id, py::return_value_policy::reference)
		.def("save", [](const RelinKeys &c, std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			c.save(out);
			out.close();
		})
		.def("load", [](RelinKeys &c, std::shared_ptr<SEALContext> &context, std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			c.load(context, in);
			in.close();
		});

	// galoisKeys.h
	py::class_<GaloisKeys, KSwitchKeys>(m, "GaloisKeys")
		.def(py::init<>())
		.def("parms_id", (parms_id_type & (GaloisKeys::KSwitchKeys::*)()) & GaloisKeys::KSwitchKeys::parms_id, py::return_value_policy::reference)
		.def("save", [](const GaloisKeys &c, std::string &path) {
			std::ofstream out(path, std::ofstream::binary);
			c.save(out);
			out.close();
		})
		.def("load", [](GaloisKeys &c, std::shared_ptr<SEALContext> &context, std::string &path) {
			std::ifstream in(path, std::ifstream::binary);
			c.load(context, in);
			in.close();
		});

	// keygenerator.h
	py::class_<KeyGenerator>(m, "KeyGenerator")
		.def(py::init<std::shared_ptr<SEALContext>>())
		.def(py::init<std::shared_ptr<SEALContext>, const SecretKey &>())
		.def(py::init<std::shared_ptr<SEALContext>, const SecretKey &, const PublicKey &>())
		.def("secret_key", &KeyGenerator::secret_key)
		.def("public_key", &KeyGenerator::public_key)
		.def("relin_keys", (RelinKeys(KeyGenerator::*)()) & KeyGenerator::relin_keys)
		.def("galois_keys", (GaloisKeys(KeyGenerator::*)(const std::vector<std::uint64_t> &)) & KeyGenerator::galois_keys)
		.def("galois_keys", (GaloisKeys(KeyGenerator::*)(const std::vector<int> &)) & KeyGenerator::galois_keys)
		.def("galois_keys", (GaloisKeys(KeyGenerator::*)()) & KeyGenerator::galois_keys);

	// encryptor.h
	py::class_<Encryptor>(m, "Encryptor")
		.def(py::init<std::shared_ptr<SEALContext>, const PublicKey &>())
		.def(py::init<std::shared_ptr<SEALContext>, const SecretKey &>())
		.def(py::init<std::shared_ptr<SEALContext>, const PublicKey &, const SecretKey &>())
		.def("encrypt", (void (Encryptor::*)(const Plaintext &, Ciphertext &, MemoryPoolHandle)) & Encryptor::encrypt,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("encrypt_zero", (void (Encryptor::*)(Ciphertext &, MemoryPoolHandle)) & Encryptor::encrypt,
			 py::arg(), py::arg() = MemoryManager::GetPool())
		.def("encrypt_zero", (void (Encryptor::*)(parms_id_type, Ciphertext &, MemoryPoolHandle)) & Encryptor::encrypt,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool());
	// symmetric

	// evaluator.h
	py::class_<Evaluator>(m, "Evaluator")
		.def(py::init<std::shared_ptr<SEALContext>>())
		.def("negate_inplace", (void (Evaluator::*)(Ciphertext &)) & Evaluator::negate_inplace)
		.def("negate", (void (Evaluator::*)(const Ciphertext &, Ciphertext &)) & Evaluator::negate)
		.def("add_inplace", (void (Evaluator::*)(Ciphertext &, const Ciphertext &)) & Evaluator::add_inplace)
		.def("add", (void (Evaluator::*)(const Ciphertext &, const Ciphertext &, Ciphertext &)) & Evaluator::add)
		.def("add_many", (void (Evaluator::*)(const std::vector<Ciphertext> &, Ciphertext &)) & Evaluator::add_many)
		.def("sub_inplace", (void (Evaluator::*)(Ciphertext &, const Ciphertext &)) & Evaluator::sub_inplace)
		.def("sub", (void (Evaluator::*)(const Ciphertext &, const Ciphertext &, Ciphertext &)) & Evaluator::sub)
		.def("multiply_inplace", (void (Evaluator::*)(Ciphertext &, const Ciphertext &, MemoryPoolHandle)) & Evaluator::multiply_inplace,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("multiply", (void (Evaluator::*)(Ciphertext &, const Ciphertext &, Ciphertext &, MemoryPoolHandle)) & Evaluator::multiply,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("square_inplace", (void (Evaluator::*)(Ciphertext &, MemoryPoolHandle)) & Evaluator::square_inplace,
			 py::arg(), py::arg() = MemoryManager::GetPool())
		.def("square", (void (Evaluator::*)(const Ciphertext &, Ciphertext &, MemoryPoolHandle)) & Evaluator::square,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("relinearize_inplace", (void (Evaluator::*)(Ciphertext &, const RelinKeys &, MemoryPoolHandle)) & Evaluator::relinearize_inplace,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("relinearize", (void (Evaluator::*)(const Ciphertext &, const RelinKeys &, Ciphertext &, MemoryPoolHandle)) & Evaluator::relinearize,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("mod_switch_to_next", (void (Evaluator::*)(const Ciphertext &, Ciphertext &, MemoryPoolHandle)) & Evaluator::mod_switch_to_next,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("mod_switch_to_next_inplace", (void (Evaluator::*)(Ciphertext &, MemoryPoolHandle)) & Evaluator::mod_switch_to_next_inplace,
			 py::arg(), py::arg() = MemoryManager::GetPool())
		.def("mod_switch_to_next_inplace", (void (Evaluator::*)(Plaintext &)) & Evaluator::mod_switch_to_next_inplace)
		.def("mod_switch_to_next", (void (Evaluator::*)(const Plaintext &, Plaintext &)) & Evaluator::mod_switch_to_next)
		.def("mod_switch_to_inplace", (void (Evaluator::*)(Ciphertext &, parms_id_type, MemoryPoolHandle)) & Evaluator::mod_switch_to_inplace,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("mod_switch_to", (void (Evaluator::*)(const Ciphertext &, parms_id_type, Ciphertext &, MemoryPoolHandle)) & Evaluator::mod_switch_to,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("mod_switch_to_inplace", (void (Evaluator::*)(Plaintext &, parms_id_type)) & Evaluator::mod_switch_to_inplace)
		.def("mod_switch_to", (void (Evaluator::*)(const Plaintext &, parms_id_type, Plaintext &)) & Evaluator::mod_switch_to)
		.def("rescale_to_next", (void (Evaluator::*)(const Ciphertext &, Ciphertext &, MemoryPoolHandle)) & Evaluator::rescale_to_next,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("rescale_to_next_inplace", (void (Evaluator::*)(Ciphertext &, MemoryPoolHandle)) & Evaluator::rescale_to_next_inplace,
			 py::arg(), py::arg() = MemoryManager::GetPool())
		.def("rescale_to_inplace", (void (Evaluator::*)(Ciphertext &, parms_id_type, MemoryPoolHandle)) & Evaluator::rescale_to_inplace,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("rescale_to", (void (Evaluator::*)(const Ciphertext &, parms_id_type, Ciphertext &, MemoryPoolHandle)) & Evaluator::rescale_to,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("multiply_many", (void (Evaluator::*)(std::vector<Ciphertext> &, const RelinKeys &, Ciphertext &, MemoryPoolHandle)) & Evaluator::multiply_many,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("exponentiate_inplace", (void (Evaluator::*)(Ciphertext &, std::uint64_t, const RelinKeys &, MemoryPoolHandle)) & Evaluator::exponentiate_inplace,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("exponentiate", (void (Evaluator::*)(const Ciphertext &, std::uint64_t, const RelinKeys &, Ciphertext &, MemoryPoolHandle)) & Evaluator::exponentiate,
			 py::arg(), py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("add_plain_inplace", (void (Evaluator::*)(Ciphertext &, const Plaintext &)) & Evaluator::add_plain_inplace)
		.def("add_plain", (void (Evaluator::*)(const Ciphertext &, const Plaintext &, Ciphertext &)) & Evaluator::add_plain)
		.def("sub_plain_inplace", (void (Evaluator::*)(Ciphertext &, const Plaintext &)) & Evaluator::sub_plain_inplace)
		.def("sub_plain", (void (Evaluator::*)(const Ciphertext &, const Plaintext &, Ciphertext &)) & Evaluator::sub_plain)
		.def("multiply_plain_inplace", (void (Evaluator::*)(Ciphertext &, const Plaintext &, MemoryPoolHandle)) & Evaluator::multiply_plain_inplace,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("multiply_plain", (void (Evaluator::*)(const Ciphertext &, const Plaintext &, Ciphertext &, MemoryPoolHandle)) & Evaluator::multiply_plain,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("transform_to_ntt_inplace", (void (Evaluator::*)(Plaintext &, parms_id_type, MemoryPoolHandle)) & Evaluator::transform_to_ntt_inplace,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("transform_to_ntt", (void (Evaluator::*)(const Plaintext &, parms_id_type, Plaintext &, MemoryPoolHandle)) & Evaluator::transform_to_ntt,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("transform_to_ntt_inplace", (void (Evaluator::*)(Ciphertext &)) & Evaluator::transform_to_ntt_inplace)
		.def("transform_to_ntt", (void (Evaluator::*)(const Ciphertext &, Ciphertext &)) & Evaluator::transform_to_ntt)
		.def("transform_from_ntt_inplace", (void (Evaluator::*)(Ciphertext &)) & Evaluator::transform_from_ntt_inplace)
		.def("transform_from_ntt", (void (Evaluator::*)(const Ciphertext &, Ciphertext &)) & Evaluator::transform_from_ntt)
		.def("apply_galois_inplace", (void (Evaluator::*)(Ciphertext &, std::uint64_t, const GaloisKeys &, MemoryPoolHandle)) & Evaluator::apply_galois_inplace,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("apply_galois", (void (Evaluator::*)(const Ciphertext &, std::uint64_t, const GaloisKeys &, Ciphertext &, MemoryPoolHandle)) & Evaluator::apply_galois,
			 py::arg(), py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("rotate_rows_inplace", (void (Evaluator::*)(Ciphertext &, int, GaloisKeys, MemoryPoolHandle)) & Evaluator::rotate_rows_inplace,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("rotate_rows", (void (Evaluator::*)(const Ciphertext &, int, const GaloisKeys &, Ciphertext &, MemoryPoolHandle)) & Evaluator::rotate_rows,
			 py::arg(), py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("rotate_columns_inplace", (void (Evaluator::*)(Ciphertext &, const GaloisKeys &, MemoryPoolHandle)) & Evaluator::rotate_columns_inplace,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("rotate_columns", (void (Evaluator::*)(const Ciphertext &, const GaloisKeys &, Ciphertext &, MemoryPoolHandle)) & Evaluator::rotate_columns,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("rotate_vector_inplace", (void (Evaluator::*)(Ciphertext &, int, const GaloisKeys &, MemoryPoolHandle)) & Evaluator::rotate_vector_inplace,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("rotate_vector", (void (Evaluator::*)(const Ciphertext &, int, const GaloisKeys &, Ciphertext &, MemoryPoolHandle)) & Evaluator::rotate_vector,
			 py::arg(), py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("complex_conjugate_inplace", (void (Evaluator::*)(Ciphertext &, const GaloisKeys &, MemoryPoolHandle)) & Evaluator::complex_conjugate_inplace,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("complex_conjugate", (void (Evaluator::*)(const Ciphertext &, const GaloisKeys &, Ciphertext &, MemoryPoolHandle)) & Evaluator::complex_conjugate,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool());

	// ckks.h
	py::class_<CKKSEncoder>(m, "CKKSEncoder")
		.def(py::init<std::shared_ptr<SEALContext>>())
		.def("encode", (void (CKKSEncoder::*)(const std::vector<double> &, parms_id_type, double, Plaintext &, MemoryPoolHandle)) & CKKSEncoder::encode,
			 py::arg(), py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("encode", (void (CKKSEncoder::*)(const std::vector<std::complex<double>> &, parms_id_type, double, Plaintext &, MemoryPoolHandle)) & CKKSEncoder::encode,
			 py::arg(), py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("encode", (void (CKKSEncoder::*)(const std::vector<double> &, double, Plaintext &, MemoryPoolHandle)) & CKKSEncoder::encode,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("encode", (void (CKKSEncoder::*)(const std::vector<std::complex<double>> &, double, Plaintext &, MemoryPoolHandle)) & CKKSEncoder::encode,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("encode", (void (CKKSEncoder::*)(double, parms_id_type, double, Plaintext &, MemoryPoolHandle)) & CKKSEncoder::encode,
			 py::arg(), py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("encode", (void (CKKSEncoder::*)(double, double, Plaintext &, MemoryPoolHandle)) & CKKSEncoder::encode,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("encode", (void (CKKSEncoder::*)(std::complex<double>, parms_id_type, double, Plaintext &, MemoryPoolHandle)) & CKKSEncoder::encode,
			 py::arg(), py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("encode", (void (CKKSEncoder::*)(std::complex<double>, double, Plaintext &, MemoryPoolHandle)) & CKKSEncoder::encode,
			 py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("encode", (void (CKKSEncoder::*)(std::int64_t, parms_id_type, Plaintext &)) & CKKSEncoder::encode,
			 py::arg(), py::arg(), py::arg())
		.def("encode", (void (CKKSEncoder::*)(std::int64_t, Plaintext &)) & CKKSEncoder::encode,
			 py::arg(), py::arg())
		.def("decode", (void (CKKSEncoder::*)(const Plaintext &, std::vector<double> &, MemoryPoolHandle)) & CKKSEncoder::decode,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("decode", (void (CKKSEncoder::*)(const Plaintext &, std::vector<std::complex<double>> &, MemoryPoolHandle)) & CKKSEncoder::decode,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("slot_count", &CKKSEncoder::slot_count);
	// gsl

	// decryptor.h
	py::class_<Decryptor>(m, "Decryptor")
		.def(py::init<std::shared_ptr<SEALContext>, const SecretKey &>())
		.def("decrypt", &Decryptor::decrypt)
		.def("invariant_noise_budget", &Decryptor::invariant_noise_budget);

	// biguint.h
	py::class_<BigUInt>(m, "BigUInt")
		.def(py::init<>())
		.def(py::init<int>())
		.def(py::init<const std::string &>())
		.def(py::init<int, const std::string &>())
		.def(py::init<int, std::uint64_t>())
		.def("bit_count", &BigUInt::bit_count)
		.def("significant_bit_count", &BigUInt::significant_bit_count)
		.def("to_double", &BigUInt::to_double)
		.def("to_string", &BigUInt::to_string)
		.def("to_dec_string", &BigUInt::to_dec_string)
		.def("resize", &BigUInt::resize);
	// gsl

	// intencoder.h
	py::class_<IntegerEncoder>(m, "IntegerEncoder")
		.def(py::init<std::shared_ptr<SEALContext>>())
		.def("encode", (Plaintext(IntegerEncoder::*)(std::uint64_t)) & IntegerEncoder::encode)
		.def("encode", (void (IntegerEncoder::*)(std::uint64_t, Plaintext &)) & IntegerEncoder::encode)
		.def("decode_uint32", &IntegerEncoder::decode_uint32)
		.def("decode_uint64", &IntegerEncoder::decode_uint64)
		.def("encode", (Plaintext(IntegerEncoder::*)(std::int64_t)) & IntegerEncoder::encode)
		.def("encode", (void (IntegerEncoder::*)(std::int64_t, Plaintext &)) & IntegerEncoder::encode)
		.def("decode_int32", &IntegerEncoder::decode_int32)
		.def("decode_int64", &IntegerEncoder::decode_int64)
		.def("encode", (Plaintext(IntegerEncoder::*)(const BigUInt &)) & IntegerEncoder::encode)
		.def("encode", (void (IntegerEncoder::*)(const BigUInt &, Plaintext &)) & IntegerEncoder::encode)
		.def("decode_biguint", &IntegerEncoder::decode_biguint);

	// batchencoder.h
	py::class_<BatchEncoder>(m, "BatchEncoder")
		.def(py::init<std::shared_ptr<SEALContext>>())
		.def("encode", (void (BatchEncoder::*)(const std::vector<std::uint64_t> &, Plaintext &)) & BatchEncoder::encode)
		.def("encode", (void (BatchEncoder::*)(const std::vector<std::int64_t> &, Plaintext &)) & BatchEncoder::encode)
		.def("encode", (void (BatchEncoder::*)(Plaintext &, MemoryPoolHandle)) & BatchEncoder::encode,
			 py::arg(), py::arg() = MemoryManager::GetPool())
		.def("decode", (void (BatchEncoder::*)(const Plaintext &, std::vector<std::uint64_t> &, MemoryPoolHandle)) & BatchEncoder::decode,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("decode", (void (BatchEncoder::*)(const Plaintext &, std::vector<std::int64_t> &, MemoryPoolHandle)) & BatchEncoder::decode,
			 py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("decode", (void (BatchEncoder::*)(Plaintext &, MemoryPoolHandle)) & BatchEncoder::decode,
			 py::arg(), py::arg() = MemoryManager::GetPool())
		.def("slot_count", &BatchEncoder::slot_count);
	//gsl
}
