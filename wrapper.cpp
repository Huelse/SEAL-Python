#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "seal/seal.h"

namespace py = pybind11;

using namespace seal;
using namespace std;


PYBIND11_MODULE(seal, m) {
	m.doc() = "SEAL For Python!";
	
	// EncryptionParameters
	py::class_<EncryptionParameters>(m, "EncryptionParameters")
		.def(py::init<std::uint8_t>())

		.def("set_poly_modulus_degree",
        (void (EncryptionParameters::*)(std::uint64_t)) &EncryptionParameters::set_poly_modulus_degree)

		.def("set_coeff_modulus",
        (void (EncryptionParameters::*)(const std::vector<SmallModulus> &)) &EncryptionParameters::set_coeff_modulus)
		
		.def("set_plain_modulus",
        (void (EncryptionParameters::*)(const SmallModulus &)) &EncryptionParameters::set_plain_modulus)

		.def("set_plain_modulus",
        (void (EncryptionParameters::*)(std::uint64_t)) &EncryptionParameters::set_plain_modulus);

	// SEALContext
	py::class_<SEALContext, std::shared_ptr<SEALContext>>(m, "SEALContext")
		.def("Create",
		[](const EncryptionParameters &parms) { return SEALContext::Create(parms); })
		
		.def("key_parms_id", &SEALContext::key_parms_id)
		
		.def("key_context_data", &SEALContext::key_context_data)

		.def("get_context_data",
		(void (SEALContext::*)(parms_id_type)) &SEALContext::get_context_data);

	// SEALContext::ContextData
	py::class_<SEALContext::ContextData>(m, "SEALContext::ContextData")
		.def("parms", &SEALContext::ContextData::parms)
		.def("parms_id", &SEALContext::ContextData::parms_id)
		.def("total_coeff_modulus", (std::uint64_t (SEALContext::ContextData::*)()) &SEALContext::ContextData::total_coeff_modulus);
	
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
		.def("public_key", &KeyGenerator::public_key);

}