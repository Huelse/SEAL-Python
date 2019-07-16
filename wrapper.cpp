#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "seal/seal.h"

namespace py = pybind11;

//using namespace pybind11::literals;
using namespace std;
using namespace seal;


PYBIND11_MODULE(seal, m) {
	m.doc() = "SEAL For Python!";

// EncryptionParameters
	py::class_<EncryptionParameters>(m, "EncryptionParameters")
		//.def(py::init<const EncryptionParameters &>())
		.def(py::init<std::uint8_t>())

		.def("set_poly_modulus_degree",
        (void (EncryptionParameters::*)(std::uint64_t)) &EncryptionParameters::set_poly_modulus_degree)

		.def("set_coeff_modulus",
        (void (EncryptionParameters::*)(const std::vector<SmallModulus> &)) &EncryptionParameters::set_coeff_modulus)
		
		.def("set_plain_modulus",
        (void (EncryptionParameters::*)(const SmallModulus &)) &EncryptionParameters::set_plain_modulus)

		.def("set_plain_modulus",
        (void (EncryptionParameters::*)(std::uint64_t)) &EncryptionParameters::set_plain_modulus)
		
		.def("scheme", &EncryptionParameters::scheme)

		.def("poly_modulus_degree", &EncryptionParameters::poly_modulus_degree)

		.def("coeff_modulus", &EncryptionParameters::coeff_modulus)

		.def("plain_modulus", &EncryptionParameters::plain_modulus);

// scheme_type
	py::enum_<scheme_type>(m, "scheme_type", py::arithmetic())
		.value("BFV", scheme_type::BFV)
		.value("CKKS", scheme_type::CKKS);


// SEALContext
	py::class_<SEALContext, std::shared_ptr<SEALContext>>(m, "SEALContext")
		.def("Create",
		[](const EncryptionParameters &parms) { return SEALContext::Create(parms); }, py::return_value_policy::reference)
		
		.def("key_parms_id", &SEALContext::key_parms_id, py::return_value_policy::reference)
		
		.def("key_context_data", &SEALContext::key_context_data, py::return_value_policy::reference)

		.def("get_context_data", (void (SEALContext::*)(parms_id_type)) &SEALContext::get_context_data);

// SEALContext::ContextData
	py::class_<SEALContext::ContextData>(m, "SEALContext::ContextData")
		.def("parms", &SEALContext::ContextData::parms, py::return_value_policy::reference)
		.def("parms_id", &SEALContext::ContextData::parms_id, py::return_value_policy::reference)
		.def("total_coeff_modulus",
		(std::uint64_t (SEALContext::ContextData::*)()) &SEALContext::ContextData::total_coeff_modulus);
	
// SmallModulus
	py::class_<SmallModulus>(m, "SmallModulus")
      	.def(py::init<>())
      	.def(py::init<std::uint64_t>())
      	.def("value", (std::uint64_t (SmallModulus::*)()) &SmallModulus::value);

// CoeffModulus
	py::class_<CoeffModulus>(m, "CoeffModulus")
		.def("BFVDefault",
		[](std::size_t poly_modulus_degree) { return CoeffModulus::BFVDefault(poly_modulus_degree); });

// SecretKey
	py::class_<SecretKey>(m, "SecretKey")
		.def(py::init<>())
		.def("save", (void (SecretKey::*)(std::ostream &)) &SecretKey::save)
		.def("load", (void (SecretKey::*)(std::shared_ptr<SEALContext>, std::istream &)) &SecretKey::load);

// PublicKey
	py::class_<PublicKey>(m, "PublicKey")
		.def(py::init<>())
		.def("save", (void (PublicKey::*)(std::ostream &)) &PublicKey::save)
		.def("load", (void (PublicKey::*)(std::shared_ptr<SEALContext>, std::istream &)) &PublicKey::load);

// KeyGenerator
	py::class_<KeyGenerator>(m, "KeyGenerator")
		.def(py::init<std::shared_ptr<SEALContext>>())
		.def(py::init<std::shared_ptr<SEALContext>, const SecretKey &>())
		.def(py::init<std::shared_ptr<SEALContext>, const SecretKey &, const PublicKey &>())
		.def("secret_key", &KeyGenerator::secret_key)
		.def("public_key", &KeyGenerator::public_key)
		.def("galois_keys", (GaloisKeys (KeyGenerator::*)(const std::vector<std::uint64_t> &)) &KeyGenerator::galois_keys)
		.def("galois_keys", (GaloisKeys (KeyGenerator::*)(const std::vector<int> &)) &KeyGenerator::galois_keys)
		.def("galois_keys", (GaloisKeys (KeyGenerator::*)()) &KeyGenerator::galois_keys);
		// inline RelinKeys relin_keys()

// MemoryPoolHandle
	py::class_<MemoryPoolHandle>(m, "MemoryPoolHandle")
		.def(py::init<>())
		.def(py::init<std::shared_ptr<util::MemoryPool>>())
		.def(py::init<const MemoryPoolHandle &>())
		.def_static("New", &MemoryPoolHandle::New)
		.def_static("Global", &MemoryPoolHandle::Global);

// Encryptor
	py::class_<Encryptor>(m, "Encryptor")
		.def(py::init<std::shared_ptr<SEALContext>, const PublicKey &>())
		.def("encrypt", (void (Encryptor::*)(const Plaintext &, Ciphertext &)) &Encryptor::encrypt);
		// void encrypt(const Plaintext &plain, Ciphertext &destination, MemoryPoolHandle pool = MemoryManager::GetPool());

// Evaluator
	py::class_<Evaluator>(m, "Evaluator")
		.def(py::init<std::shared_ptr<SEALContext>>())
		.def("negate_inplace", (void (Evaluator::*)(Ciphertext &)) &Evaluator::negate)
		.def("negate", (void (Evaluator::*)(const Ciphertext &, Ciphertext &)) &Evaluator::negate)
		.def("add_inplace", (void (Evaluator::*)(Ciphertext &, const Ciphertext &)) &Evaluator::add_inplace)
		.def("add", (void (Evaluator::*)(const Ciphertext &, const Ciphertext &, Ciphertext &)) &Evaluator::add)
		.def("sub_inplace", (void (Evaluator::*)(Ciphertext &, const Ciphertext &)) &Evaluator::sub_inplace)
		.def("sub", (void (Evaluator::*)(const Ciphertext &, const Ciphertext &, Ciphertext &)) &Evaluator::sub)
		.def("multiply_inplace", (void (Evaluator::*)(Ciphertext &, const Ciphertext &)) &Evaluator::multiply_inplace)
		.def("multiply", (void (Evaluator::*)(Ciphertext &, const Ciphertext &, Ciphertext &)) &Evaluator::multiply)
		.def("square_inplace", (void (Evaluator::*)(Ciphertext &)) &Evaluator::square_inplace)
		.def("square", (void (Evaluator::*)(const Ciphertext &, Ciphertext &)) &Evaluator::square);

}

