#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/complex.h>
#include "seal/seal.h"

namespace py = pybind11;

using namespace std;
using namespace seal;

using pt_coeff_type = std::uint64_t;
using size_type = IntArray<pt_coeff_type>::size_type;

PYBIND11_MAKE_OPAQUE(std::vector<double>);
PYBIND11_MAKE_OPAQUE(std::vector<std::complex<double>>);
PYBIND11_MAKE_OPAQUE(std::vector<std::uint64_t>);
PYBIND11_MAKE_OPAQUE(std::vector<std::int64_t>);

using DoubleVector = std::vector<double>;
using ComplexDoubleVector = std::vector<std::complex<double>>;
using uIntVector = std::vector<std::uint64_t>;
using IntVector = std::vector<std::int64_t>;

PYBIND11_MODULE(seal, m)
{

	m.doc() = "SEAL For Python. From https://github.com/Huelse/SEAL-Python";

	// ComplexDoubleVector
	py::class_<ComplexDoubleVector>(m, "ComplexDoubleVector", py::buffer_protocol())
		.def_buffer([](ComplexDoubleVector &v) -> py::buffer_info {
            return py::buffer_info(
                v.data(),
                sizeof(std::complex<double>),
                py::format_descriptor<std::complex<double>>::format(),
                1,
                { v.size() },
                { sizeof(std::complex<double>) }
            );
        })
		.def(py::init<>())
		.def("pop_back", &ComplexDoubleVector::pop_back)
		.def("push_back", (void (ComplexDoubleVector::*)(const std::complex<double> &)) & ComplexDoubleVector::push_back)
		.def("back", (std::complex<double> & (ComplexDoubleVector::*)()) & ComplexDoubleVector::back)
		.def("__len__", [](const ComplexDoubleVector &v) { return v.size(); })
		.def("__setitem__", [](ComplexDoubleVector &v, const std::uint64_t i, const std::complex<double> &value) {
			if (i >= v.size())
				throw py::index_error();
			if (i >= 0)
				v[i] = value;
			else
				v[v.size() - i] = value;
		})
		.def("__getitem__", [](const ComplexDoubleVector &v, int i) {
			return v[i];
		},
			 py::keep_alive<1, 2>())
		.def("__iter__", [](std::vector<std::complex<double>> &v) {
			return py::make_iterator(v.begin(), v.end());
		},
			 py::keep_alive<0, 1>());

	// DoubleVector
	py::class_<DoubleVector>(m, "DoubleVector", py::buffer_protocol())
		.def_buffer([](DoubleVector &v) -> py::buffer_info {
            return py::buffer_info(
                v.data(),
                sizeof(double),
                py::format_descriptor<double>::format(),
                1,
                { v.size() },
                { sizeof(double) }
            );
        })
		.def(py::init<>())
		.def("pop_back", &DoubleVector::pop_back)
		.def("push_back", (void (DoubleVector::*)(const double &)) & DoubleVector::push_back)
		.def("back", (double &(DoubleVector::*)()) & DoubleVector::back)
		.def("__len__", [](const DoubleVector &v) { return v.size(); })
		.def("__setitem__", [](DoubleVector &v, const std::uint64_t i, const double &value) {
			if (i >= v.size())
				throw py::index_error();
			if (i >= 0)
				v[i] = value;
			else
				v[v.size() - i] = value;
		})
		.def("__getitem__", [](const DoubleVector &v, int i) {
			return v[i];
		},
			 py::keep_alive<1, 2>())
		.def("__iter__", [](std::vector<double> &v) {
			return py::make_iterator(v.begin(), v.end());
		},
			 py::keep_alive<0, 1>());

	// uIntVector
	py::class_<uIntVector>(m, "uIntVector", py::buffer_protocol())
		.def_buffer([](uIntVector &v) -> py::buffer_info {
            return py::buffer_info(
                v.data(),
                sizeof(std::uint64_t),
                py::format_descriptor<std::uint64_t>::format(),
                1,
                { v.size() },
                { sizeof(std::uint64_t) }
            );
        })
		.def(py::init<>())
		.def("pop_back", &uIntVector::pop_back)
		.def("push_back", (void (uIntVector::*)(const std::uint64_t &)) & uIntVector::push_back)
		.def("back", (std::uint64_t & (uIntVector::*)()) & uIntVector::back)
		.def("__len__", [](const uIntVector &v) { return v.size(); })
		.def("__setitem__", [](uIntVector &v, const std::uint64_t i, const std::uint64_t &value) {
			if (i >= v.size())
				throw py::index_error();
			if (i >= 0)
				v[i] = value;
			else
				v[v.size() - i] = value;
		})
		.def("__getitem__", [](const uIntVector &v, int i) {
			return v[i];
		},
			 py::keep_alive<1, 2>())
		.def("__iter__", [](std::vector<std::uint64_t> &v) {
			return py::make_iterator(v.begin(), v.end());
		},
			 py::keep_alive<0, 1>());

	// IntVector
	py::class_<IntVector>(m, "IntVector", py::buffer_protocol())
		.def_buffer([](IntVector &v) -> py::buffer_info {
            return py::buffer_info(
                v.data(),
                sizeof(std::int64_t),
                py::format_descriptor<std::int64_t>::format(),
                1,
                { v.size() },
                { sizeof(std::int64_t) }
            );
        })
		.def(py::init<>())
		.def("pop_back", &IntVector::pop_back)
		.def("push_back", (void (IntVector::*)(const std::int64_t &)) & IntVector::push_back)
		.def("back", (std::int64_t & (IntVector::*)()) & IntVector::back)
		.def("__len__", [](const IntVector &v) { return v.size(); })
		.def("__setitem__", [](IntVector &v, const std::uint64_t i, const std::int64_t &value) {
			if (i >= v.size())
				throw py::index_error();
			if (i >= 0)
				v[i] = value;
			else
				v[v.size() - i] = value;
		})
		.def("__getitem__", [](const IntVector &v, int i) {
			return v[i];
		},
			 py::keep_alive<1, 2>())
		.def("__iter__", [](std::vector<std::int64_t> &v) {
			return py::make_iterator(v.begin(), v.end());
		},
			 py::keep_alive<0, 1>());

	// BigUInt
	py::class_<BigUInt>(m, "BigUInt")
		.def(py::init<>())
		.def("to_double", &BigUInt::to_double)
		.def("significant_bit_count", (int (BigUInt::*)()) & BigUInt::significant_bit_count);

	// EncryptionParameters
	py::class_<EncryptionParameters>(m, "EncryptionParameters")
		.def(py::init<std::uint8_t>())

		.def("set_poly_modulus_degree",
			 (void (EncryptionParameters::*)(std::uint64_t)) & EncryptionParameters::set_poly_modulus_degree)

		.def("set_coeff_modulus",
			 (void (EncryptionParameters::*)(const std::vector<SmallModulus> &)) & EncryptionParameters::set_coeff_modulus)

		.def("set_plain_modulus",
			 (void (EncryptionParameters::*)(const SmallModulus &)) & EncryptionParameters::set_plain_modulus)

		.def("set_plain_modulus",
			 (void (EncryptionParameters::*)(std::uint64_t)) & EncryptionParameters::set_plain_modulus)

		.def("scheme", &EncryptionParameters::scheme)

		.def("poly_modulus_degree", &EncryptionParameters::poly_modulus_degree)

		.def("coeff_modulus", &EncryptionParameters::coeff_modulus)

		.def("plain_modulus", &EncryptionParameters::plain_modulus);

	// scheme_type
	py::enum_<scheme_type>(m, "scheme_type", py::arithmetic())
		.value("BFV", scheme_type::BFV)
		.value("CKKS", scheme_type::CKKS);

	// sec_level_type
	py::enum_<sec_level_type>(m, "sec_level_type", py::arithmetic())
		.value("none", sec_level_type::none)
		.value("tc128", sec_level_type::tc128)
		.value("tc192", sec_level_type::tc192)
		.value("tc256", sec_level_type::tc256);

	// EncryptionParameterQualifiers
	py::class_<EncryptionParameterQualifiers,
			   std::unique_ptr<EncryptionParameterQualifiers, py::nodelete>>(m, "EncryptionParameterQualifiers")
		.def_readwrite("parameters_set", &EncryptionParameterQualifiers::parameters_set)
		.def_readwrite("using_fft", &EncryptionParameterQualifiers::using_fft)
		.def_readwrite("using_ntt", &EncryptionParameterQualifiers::using_ntt)
		.def_readwrite("using_batching", &EncryptionParameterQualifiers::using_batching)
		.def_readwrite("using_fast_plain_lift", &EncryptionParameterQualifiers::using_fast_plain_lift)
		.def_readwrite("using_descending_modulus_chain", &EncryptionParameterQualifiers::using_descending_modulus_chain)
		.def_readwrite("sec_level", &EncryptionParameterQualifiers::sec_level);

	// SEALContext
	py::class_<SEALContext, std::shared_ptr<SEALContext>>(m, "SEALContext")
		.def("Create", [](const EncryptionParameters &parms) { return SEALContext::Create(parms); })
		.def("Create", [](const EncryptionParameters &parms, bool expand_mod_chain) { return SEALContext::Create(parms, expand_mod_chain); })
		.def("get_context_data", &SEALContext::get_context_data, py::return_value_policy::reference)
		.def("key_context_data", &SEALContext::key_context_data, py::return_value_policy::reference)
		.def("first_context_data", &SEALContext::first_context_data, py::return_value_policy::reference)
		.def("first_parms_id", &SEALContext::first_parms_id, py::return_value_policy::reference)
		.def("last_parms_id", &SEALContext::last_parms_id, py::return_value_policy::reference)
		.def("using_keyswitching", &SEALContext::using_keyswitching);

	// SEALContext::ContextData
	py::class_<SEALContext::ContextData, std::shared_ptr<SEALContext::ContextData>>(m, "SEALContext::ContextData")
		.def("parms", &SEALContext::ContextData::parms)
		.def("parms_id", &SEALContext::ContextData::parms_id)
		.def("qualifiers", &SEALContext::ContextData::qualifiers)
		.def("total_coeff_modulus",
			 (std::uint64_t(SEALContext::ContextData::*)()) & SEALContext::ContextData::total_coeff_modulus)
		.def("total_coeff_modulus_bit_count", &SEALContext::ContextData::total_coeff_modulus_bit_count)
		.def("next_context_data", &SEALContext::ContextData::next_context_data)
		.def("chain_index", &SEALContext::ContextData::chain_index);

	// SmallModulus
	py::class_<SmallModulus>(m, "SmallModulus")
		.def(py::init<>())
		.def(py::init<std::uint64_t>())
		.def("bit_count", &SmallModulus::bit_count)
		.def("value", (std::uint64_t(SmallModulus::*)()) & SmallModulus::value);

	// CoeffModulus
	py::class_<CoeffModulus>(m, "CoeffModulus")
		.def("BFVDefault",
			 [](std::size_t poly_modulus_degree) { return CoeffModulus::BFVDefault(poly_modulus_degree); })
		.def("Create",
			 [](std::size_t poly_modulus_degree, std::vector<int> bit_sizes) { return CoeffModulus::Create(poly_modulus_degree, bit_sizes); });

	// PlainModulus
	py::class_<PlainModulus>(m, "PlainModulus")
		.def("Batching",
			 [](std::size_t poly_modulus_degree, int bit_size) { return PlainModulus::Batching(poly_modulus_degree, bit_size); })
		.def("Batching",
			 [](std::size_t poly_modulus_degree, std::vector<int> bit_sizes) { return PlainModulus::Batching(poly_modulus_degree, bit_sizes); });

	// SecretKey
	py::class_<SecretKey>(m, "SecretKey")
		.def(py::init<>())
		.def("parms_id", (parms_id_type & (SecretKey::*)()) & SecretKey::parms_id, py::return_value_policy::reference)
		.def("save", (void (SecretKey::*)(std::ostream &)) & SecretKey::save)
		.def("load", (void (SecretKey::*)(std::shared_ptr<SEALContext>, std::istream &)) & SecretKey::load);

	// PublicKey
	py::class_<PublicKey>(m, "PublicKey")
		.def(py::init<>())
		.def("parms_id", (parms_id_type & (PublicKey::*)()) & PublicKey::parms_id, py::return_value_policy::reference)
		.def("save", (void (PublicKey::*)(std::ostream &)) & PublicKey::save)
		.def("load", (void (PublicKey::*)(std::shared_ptr<SEALContext>, std::istream &)) & PublicKey::load);

	// KSwitchKeys
	py::class_<KSwitchKeys>(m, "KSwitchKeys")
		.def(py::init<>())
		.def("parms_id", (parms_id_type & (KSwitchKeys::*)()) & KSwitchKeys::parms_id, py::return_value_policy::reference);

	// RelinKeys
	py::class_<RelinKeys, KSwitchKeys>(m, "RelinKeys")
		.def(py::init<>())
		.def("parms_id", (parms_id_type & (RelinKeys::KSwitchKeys::*)()) & RelinKeys::KSwitchKeys::parms_id, py::return_value_policy::reference);

	// GaloisKeys
	py::class_<GaloisKeys, KSwitchKeys>(m, "GaloisKeys")
		.def(py::init<>())
		.def("parms_id", (parms_id_type & (GaloisKeys::KSwitchKeys::*)()) & GaloisKeys::KSwitchKeys::parms_id, py::return_value_policy::reference);

	// KeyGenerator
	py::class_<KeyGenerator>(m, "KeyGenerator")
		.def(py::init<std::shared_ptr<SEALContext>>())
		.def(py::init<std::shared_ptr<SEALContext>, const SecretKey &>())
		.def(py::init<std::shared_ptr<SEALContext>, const SecretKey &, const PublicKey &>())
		.def("secret_key", &KeyGenerator::secret_key)
		.def("public_key", &KeyGenerator::public_key)
		.def("galois_keys", (GaloisKeys(KeyGenerator::*)(const std::vector<std::uint64_t> &)) & KeyGenerator::galois_keys)
		.def("galois_keys", (GaloisKeys(KeyGenerator::*)(const std::vector<int> &)) & KeyGenerator::galois_keys)
		.def("galois_keys", (GaloisKeys(KeyGenerator::*)()) & KeyGenerator::galois_keys)
		.def("relin_keys", (RelinKeys(KeyGenerator::*)()) & KeyGenerator::relin_keys);

	// MemoryPoolHandle
	py::class_<MemoryPoolHandle>(m, "MemoryPoolHandle")
		.def(py::init<>())
		.def(py::init<std::shared_ptr<util::MemoryPool>>())
		.def_static("New", &MemoryPoolHandle::New)
		.def_static("Global", &MemoryPoolHandle::Global);

	// MemoryManager
	py::class_<MemoryManager>(m, "MemoryManager")
		.def(py::init<>())
		.def("GetPool", []() { return MemoryManager::GetPool(); });

	// Ciphertext
	py::class_<Ciphertext>(m, "Ciphertext")
		.def(py::init<>())
		.def(py::init<std::shared_ptr<SEALContext>>())
		.def(py::init<std::shared_ptr<SEALContext>, parms_id_type>())
		.def(py::init<const Ciphertext &>())
		.def("size", &Ciphertext::size)
		.def("scale", (double &(Ciphertext::*)()) & Ciphertext::scale)
		.def("reserve", (void (Ciphertext::*)(size_type)) & Ciphertext::reserve)
		.def("set_scale", (void (Ciphertext::*)(double)) & Ciphertext::set_scale)
		.def("parms_id", (parms_id_type & (Ciphertext::*)()) & Ciphertext::parms_id, py::return_value_policy::reference);

	// Plaintext
	py::class_<Plaintext>(m, "Plaintext")
		.def(py::init<>())
		.def(py::init<size_type>())
		.def(py::init<size_type, size_type>())
		.def(py::init<const std::string &>())
		.def(py::init<const Plaintext &>())
		.def("data", (pt_coeff_type * (Plaintext::*)(size_type)) & Plaintext::data)
		.def("significant_coeff_count", &Plaintext::significant_coeff_count)
		.def("to_string", &Plaintext::to_string)
		.def("coeff_count", &Plaintext::coeff_count)
		.def("save", (void (Plaintext::*)(std::ostream &)) & Plaintext::save)
		.def("load", (void (Plaintext::*)(std::shared_ptr<SEALContext>, std::istream &)) & Plaintext::load)
		.def("scale", (double &(Plaintext::*)()) & Plaintext::scale)
		.def("parms_id", (parms_id_type & (Plaintext::*)()) & Plaintext::parms_id, py::return_value_policy::reference);

	// Encryptor
	py::class_<Encryptor>(m, "Encryptor")
		.def(py::init<std::shared_ptr<SEALContext>, const PublicKey &>())
		.def("encrypt", (void (Encryptor::*)(const Plaintext &, Ciphertext &)) & Encryptor::encrypt);

	// Evaluator
	py::class_<Evaluator>(m, "Evaluator")
		.def(py::init<std::shared_ptr<SEALContext>>())
		.def("negate_inplace", (void (Evaluator::*)(Ciphertext &)) & Evaluator::negate_inplace)
		.def("negate", (void (Evaluator::*)(const Ciphertext &, Ciphertext &)) & Evaluator::negate)
		.def("add_inplace", (void (Evaluator::*)(Ciphertext &, const Ciphertext &)) & Evaluator::add_inplace)
		.def("add", (void (Evaluator::*)(const Ciphertext &, const Ciphertext &, Ciphertext &)) & Evaluator::add)
		.def("add_many", (void (Evaluator::*)(const std::vector<Ciphertext> &, Ciphertext &)) & Evaluator::add_many)
		.def("sub_inplace", (void (Evaluator::*)(Ciphertext &, const Ciphertext &)) & Evaluator::sub_inplace)
		.def("sub", (void (Evaluator::*)(const Ciphertext &, const Ciphertext &, Ciphertext &)) & Evaluator::sub)
		.def("multiply_inplace", (void (Evaluator::*)(Ciphertext &, const Ciphertext &, MemoryPoolHandle)) & Evaluator::multiply_inplace, py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("multiply", (void (Evaluator::*)(Ciphertext &, const Ciphertext &, Ciphertext &, MemoryPoolHandle)) & Evaluator::multiply, py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("square_inplace", (void (Evaluator::*)(Ciphertext &, MemoryPoolHandle)) & Evaluator::square_inplace, py::arg(), py::arg() = MemoryManager::GetPool())
		.def("square", (void (Evaluator::*)(const Ciphertext &, Ciphertext &, MemoryPoolHandle)) & Evaluator::square, py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("relinearize_inplace", (void (Evaluator::*)(Ciphertext &, const RelinKeys &, MemoryPoolHandle)) & Evaluator::relinearize_inplace, py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("relinearize", (void (Evaluator::*)(const Ciphertext &, const RelinKeys &, Ciphertext &)) & Evaluator::relinearize)
		.def("mod_switch_to_next_inplace", (void (Evaluator::*)(Ciphertext &, MemoryPoolHandle)) & Evaluator::mod_switch_to_next_inplace, py::arg(), py::arg() = MemoryManager::GetPool())
		.def("mod_switch_to_next_inplace", (void (Evaluator::*)(Plaintext &)) & Evaluator::mod_switch_to_next_inplace)
		.def("mod_switch_to_inplace", (void (Evaluator::*)(Ciphertext &, parms_id_type, MemoryPoolHandle)) & Evaluator::mod_switch_to_inplace, py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("mod_switch_to_inplace", (void (Evaluator::*)(Plaintext &, parms_id_type)) & Evaluator::mod_switch_to_inplace)
		.def("rescale_to_next_inplace", (void (Evaluator::*)(Ciphertext &, MemoryPoolHandle)) & Evaluator::rescale_to_next_inplace, py::arg(), py::arg() = MemoryManager::GetPool())
		.def("multiply_many", (void (Evaluator::*)(std::vector<Ciphertext> &, const RelinKeys &, Ciphertext &)) & Evaluator::multiply_many)
		.def("exponentiate_inplace", (void (Evaluator::*)(Ciphertext &, std::uint64_t, const RelinKeys &)) & Evaluator::exponentiate_inplace)
		.def("exponentiate", (void (Evaluator::*)(const Ciphertext &, std::uint64_t, const RelinKeys &, Ciphertext &)) & Evaluator::exponentiate)
		.def("add_plain_inplace", (void (Evaluator::*)(Ciphertext &, const Plaintext &)) & Evaluator::add_plain_inplace)
		.def("add_plain", (void (Evaluator::*)(const Ciphertext &, const Plaintext &, Ciphertext &)) & Evaluator::add_plain)
		.def("sub_plain_inplace", (void (Evaluator::*)(Ciphertext &, const Plaintext &)) & Evaluator::sub_plain_inplace)
		.def("sub_plain", (void (Evaluator::*)(const Ciphertext &, const Plaintext &)) & Evaluator::sub_plain)
		.def("multiply_plain_inplace", (void (Evaluator::*)(Ciphertext &, const Plaintext &, MemoryPoolHandle)) & Evaluator::multiply_plain_inplace, py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("multiply_plain", (void (Evaluator::*)(const Ciphertext &, const Plaintext &, Ciphertext &, MemoryPoolHandle)) & Evaluator::multiply_plain, py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("transform_to_ntt_inplace", (void (Evaluator::*)(Ciphertext &)) & Evaluator::transform_to_ntt_inplace)
		.def("transform_to_ntt", (void (Evaluator::*)(const Ciphertext &, Ciphertext &)) & Evaluator::transform_to_ntt)
		.def("transform_from_ntt_inplace", (void (Evaluator::*)(Ciphertext &)) & Evaluator::transform_from_ntt_inplace)
		.def("transform_from_ntt", (void (Evaluator::*)(const Ciphertext &, Ciphertext &)) & Evaluator::transform_from_ntt)
		.def("apply_galois_inplace", (void (Evaluator::*)(Ciphertext &, std::uint64_t, const GaloisKeys &)) & Evaluator::apply_galois_inplace)
		.def("apply_galois", (void (Evaluator::*)(const Ciphertext &, std::uint64_t, const GaloisKeys &, Ciphertext &)) & Evaluator::apply_galois)
		.def("rotate_rows_inplace", (void (Evaluator::*)(Ciphertext &, int, GaloisKeys, MemoryPoolHandle)) & Evaluator::rotate_rows_inplace, py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("rotate_rows", (void (Evaluator::*)(const Ciphertext &, int, const GaloisKeys &, Ciphertext &)) & Evaluator::rotate_rows)
		.def("rotate_columns_inplace", (void (Evaluator::*)(Ciphertext &, const GaloisKeys &, MemoryPoolHandle)) & Evaluator::rotate_columns_inplace, py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("rotate_columns", (void (Evaluator::*)(const Ciphertext &, const GaloisKeys &, Ciphertext &)) & Evaluator::rotate_columns)
		.def("rotate_vector_inplace", (void (Evaluator::*)(Ciphertext &, int, const GaloisKeys &, MemoryPoolHandle)) & Evaluator::rotate_vector_inplace, py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("rotate_vector", (void (Evaluator::*)(const Ciphertext &, int, const GaloisKeys &, Ciphertext &, MemoryPoolHandle)) & Evaluator::rotate_vector, py::arg(), py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("complex_conjugate_inplace", (void (Evaluator::*)(Ciphertext &, const GaloisKeys &, MemoryPoolHandle)) & Evaluator::complex_conjugate_inplace, py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("complex_conjugate", (void (Evaluator::*)(const Ciphertext &, const GaloisKeys &, Ciphertext &)) & Evaluator::complex_conjugate);

	// CKKSEncoder
	py::class_<CKKSEncoder>(m, "CKKSEncoder")
		.def(py::init<std::shared_ptr<SEALContext>>())
		.def("encode", (void (CKKSEncoder::*)(const DoubleVector &, double, Plaintext &, MemoryPoolHandle)) & CKKSEncoder::encode, py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("encode", (void (CKKSEncoder::*)(const ComplexDoubleVector &, double, Plaintext &, MemoryPoolHandle)) & CKKSEncoder::encode, py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("encode", (void (CKKSEncoder::*)(double, parms_id_type, double, Plaintext &, MemoryPoolHandle)) & CKKSEncoder::encode, py::arg(), py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("encode", (void (CKKSEncoder::*)(double, double, Plaintext &, MemoryPoolHandle)) & CKKSEncoder::encode, py::arg(), py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("encode", (void (CKKSEncoder::*)(std::int64_t, Plaintext &)) & CKKSEncoder::encode)
		.def("decode", (void (CKKSEncoder::*)(const Plaintext &, DoubleVector &, MemoryPoolHandle)) & CKKSEncoder::decode, py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("decode", (void (CKKSEncoder::*)(const Plaintext &, ComplexDoubleVector &, MemoryPoolHandle)) & CKKSEncoder::decode, py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("slot_count", &CKKSEncoder::slot_count);

	// Decryptor
	py::class_<Decryptor>(m, "Decryptor")
		.def(py::init<std::shared_ptr<SEALContext>, const SecretKey &>())
		.def("decrypt", (int (Decryptor::*)(const Ciphertext &, Plaintext &)) & Decryptor::decrypt)
		.def("invariant_noise_budget", (int (Decryptor::*)(const Ciphertext &)) & Decryptor::invariant_noise_budget);

	// IntegerEncoder
	py::class_<IntegerEncoder>(m, "IntegerEncoder")
		.def(py::init<std::shared_ptr<SEALContext>>())
		.def("encode", (Plaintext(IntegerEncoder::*)(std::uint64_t)) & IntegerEncoder::encode)
		.def("encode", (Plaintext(IntegerEncoder::*)(std::int64_t)) & IntegerEncoder::encode)
		.def("encode", (void (IntegerEncoder::*)(std::uint64_t, Plaintext &)) & IntegerEncoder::encode)
		.def("decode_int32", (std::int32_t(IntegerEncoder::*)(const Plaintext &)) & IntegerEncoder::decode_int32);

	// BatchEncoder
	py::class_<BatchEncoder>(m, "BatchEncoder")
		.def(py::init<std::shared_ptr<SEALContext>>())
		.def("encode", (void (BatchEncoder::*)(const uIntVector &, Plaintext &)) & BatchEncoder::encode)
		.def("encode", (void (BatchEncoder::*)(const IntVector &, Plaintext &)) & BatchEncoder::encode)
		.def("decode", (void (BatchEncoder::*)(const Plaintext &, uIntVector &, MemoryPoolHandle)) & BatchEncoder::decode, py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("decode", (void (BatchEncoder::*)(const Plaintext &, IntVector &, MemoryPoolHandle)) & BatchEncoder::decode, py::arg(), py::arg(), py::arg() = MemoryManager::GetPool())
		.def("slot_count", &BatchEncoder::slot_count);
}
