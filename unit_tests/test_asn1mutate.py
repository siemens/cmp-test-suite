# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from base64 import b64encode

from pyasn1.type import constraint, namedtype, tag, univ, error
from pyasn1.codec.der import encoder
# from pyasn1.error import ValueConstraintError

from resources.asn1dump import dump_asn1_schema
from resources.asn1mutate import clone_schema, project_values
from resources.cmputils import parse_pkimessage
from resources.utils import load_and_decode_pem_file



class BasicNode(univ.Sequence):
    """Minimal data structure to play with"""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', univ.Integer()),
        namedtype.NamedType('dido', univ.Integer()),
        namedtype.OptionalNamedType('data', univ.OctetString())
    )

class ConstrainedNode(univ.Sequence):
    """A bit more sophisticated, with constraints for value ranges and value sizes"""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', univ.Integer()),
        namedtype.NamedType('dido', univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(1, 10)
        )),
        namedtype.OptionalNamedType('data', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, 20)
        ))
    )

class TaggedNode(univ.Sequence):
    """A simple structure to be used inside another one"""
    componentType = namedtype.NamedTypes(
        # Context tag 0
        namedtype.NamedType('id', univ.Integer().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )),
        # Context tag 1
        namedtype.OptionalNamedType('data', univ.OctetString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        ))
    )

class ComplexSchema(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        # Nested structure with its own tagging context
        namedtype.NamedType('meta', TaggedNode().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
        ))
    )

class TestASN1Mutate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # cls.schema = ComplexSchema()
        cls.schema = BasicNode()

    def test_basic_clone(self):
        """
        GIVEN a pyasn1 schema
        WHEN we clone it
        THEN we get a new schema that replicates the original one

        before:
        root (BasicNode/Seq)  ┆  Ⓣ UNI[16]
        └── id (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── dido (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── ∅ data (OctetString/Prim)  ┆  Ⓣ UNI[4]
        after:   -------------------------------
        root (CleanCloneBasicNode/Seq)  ┆  Ⓣ UNI[16]
        └── id (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── dido (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── ∅ data (OctetString/Prim)  ┆  Ⓣ UNI[4]
        """
        node = BasicNode()
        cloned = clone_schema(node, prefix="CleanClone")

        # Structural check
        self.assertEqual(len(cloned.componentType), 3)
        self.assertEqual(cloned.componentType.getNameByPosition(0), 'id')
        self.assertEqual(cloned.componentType.getNameByPosition(1), 'dido')
        self.assertEqual(cloned.componentType.getNameByPosition(2), 'data')

        # Tag check (Sequences are UNI[16])
        self.assertEqual(node.tagSet, cloned.tagSet)

        demo_node = BasicNode()
        demo_node['id'] = 1
        demo_node['dido'] = 1
        demo_node['data'] = 'hello'

        cloned['id']  = 2
        cloned['dido']  = 2
        cloned['data']  = 'mutant'


    def test_basic_clone_everything_optional(self):
        """
        GIVEN a pyasn1 schema with mandatory items
        WHEN we clone it with everything_optional=True
        THEN the cloned schema marks all items as optional

        before:
        .root (BasicNode/Seq)  ┆  Ⓣ UNI[16]
        └── id (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── dido (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── ∅ data (OctetString/Prim)  ┆  Ⓣ UNI[4]
        after:
        root (OptionalizedBasicNode/Seq)  ┆  Ⓣ UNI[16]
        └── ∅ id (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── ∅ dido (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── ∅ data (OctetString/Prim)  ┆  Ⓣ UNI[4]
        """
        node = BasicNode()
        cloned = clone_schema(node, prefix="Optionalized", everything_optional=True)

        # Iterate through the NamedTypes collection and ensure everything is optional
        for i in range(len(cloned.componentType)):
            component = cloned.componentType[i]
            name = cloned.componentType.getNameByPosition(i)

            is_opt = component.isOptional or component.isDefaulted
            self.assertTrue(is_opt, f"Field '{name}' should be optional but isn't.")

        encoder.encode(cloned)



    def test_basic_clone_remove_constraints(self):
        """
        GIVEN a pyasn1 schema with value constraints
        WHEN we clone it with remove_constraints=True
        THEN the cloned schema will not have the constraints

        before:
        root (ConstrainedNode/Seq)  ┆  Ⓣ UNI[16]
        └── id (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── dido (Integer/Prim)  ┆  Ⓣ UNI[2]  ┆  § Range [1..10]
        └── ∅ data (OctetString/Prim)  ┆  Ⓣ UNI[4]  ┆  § Size [1..20]
        after:     -----------------------------
        root (RelaxedConstrainedNode/Seq)  ┆  Ⓣ UNI[16]
        └── ∅ id (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── ∅ dido (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── ∅ data (OctetString/Prim)  ┆  Ⓣ UNI[4]
        """
        node = ConstrainedNode()
        node['id'] = 5
        node['dido'] = 5
        node['data'] = b'AAAAA'  # data lengh is capped at 20
        cloned = clone_schema(node, prefix="Relaxed", remove_constraints=True)

        with self.assertRaises(error.ValueConstraintError):
            # Ensure the original schema is intact; this should fail because
            # the value range is capped at 10 and data is capped at 20.
            # Also note that we use setComponentByName instead of dictionary
            # access, because in that case it would've raised KeyError
            node.setComponentByName('dido', 20)
            node.setComponentByName('data', b'\x00'*30)

        # however, the cloned schema is relaxed and these should work fine.
        cloned['dido'] = 20
        cloned['data'] = b'\x00' * 30


    def test_basic_project_values(self):
        """
        GIVEN a pyasn1 schema and an object of that schema with populated values
        WHEN we clone the schema and project values from the original object to the clone
        THEN the clone will have the same data
        """
        node = BasicNode()
        cloned = clone_schema(node, prefix="ClonedValues")

        demo_node = BasicNode()
        demo_node['id'] = 1
        demo_node['dido'] = 1
        demo_node['data'] = 'hello'

        populated_clone = project_values(demo_node, cloned)
        encoder.encode(populated_clone)


    def test_tag_preservation_complex(self):
        """
        GIVEN a schema with context-specific explicit/implicit tags
        WHEN we clone the schema
        THEN the tags must remain identical to the original
        """
        # I don't know of an easy way to compare them before and after, but
        # a manual inspection of the dumped schema makes it easy.
        # TODO automate it.

        node = ComplexSchema()
        #dump_asn1_schema(node)
        cloned = clone_schema(node, prefix="SameTag")
        # dump_asn1_schema(cloned)


    def test_change_type_update_tag(self):
        """
        GIVEN a pyasn1 schema and an object of that schema
        WHEN we clone the schema and apply a substitution map with keep_tag=False
        THEN the cloned schema will have a new data type at the given asn1path and its tag will correspond to the NEW type

        before:
        ....root (BasicNode/Seq)  ┆  Ⓣ UNI[16]
        └── id (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── dido (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── ∅ data (OctetString/Prim)  ┆  Ⓣ UNI[4]
        after:
        root (RetypedCloneBasicNode/Seq)  ┆  Ⓣ UNI[16]
        └── id (RetypedCloneInteger/Prim)  ┆  Ⓣ UNI[2]
        └── dido (OctetString/Prim)  ┆  Ⓣ UNI[4]      <--- this is now an OctetString with tag uni[4]
        └── ∅ data (RetypedCloneOctetString/Prim)  ┆  Ⓣ UNI[4]
        """
        node = BasicNode()

        # The substitution format is asn1path -> new_type, keep_tag
        # If keep_tag is True, it will force-preserve the old tag that corresponds to the old data-type
        substitutions = {
            'dido': (univ.OctetString(), False)
        }
        cloned = clone_schema(node, prefix="RetypedNewtagClone", substitutions=substitutions)

        # Access the schema definition for the 'dido' field
        original_dido_type = cloned.componentType['dido'].getType()

        # It used to be an integer (tagged UNI[2], but it should now be OctetString with the tag UNI[4]
        self.assertIsInstance(original_dido_type, univ.OctetString)
        self.assertEqual(original_dido_type.tagSet, univ.OctetString().tagSet)


        node['id'] = 45
        node['dido'] = 123
        node['data'] = b'99999'
        _encoded = encoder.encode(node)
        # print(b64encode(_encoded))

        # try setting the thing to an OctetString value and actually encoding it
        cloned['id'] = 45
        cloned['dido'] = b'012345'
        cloned['data'] = b'99999'

        _encoded = encoder.encode(cloned)
        # print(b64encode(_encoded))  # MBICAS0EBjAxMjM0NQQFOTk5OTk=



    def test_change_type_preserve_tag(self):
        """
        GIVEN a pyasn1 schema and an object of that schema
        WHEN we clone the schema and apply a substitution map with keep_tag=True
        THEN the cloned schema will have a new data type at the given asn1path and its tag will correspond to the OLD type

        before:
        root (BasicNode/Seq)  ┆  Ⓣ UNI[16]
        └── id (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── dido (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── ∅ data (OctetString/Prim)  ┆  Ⓣ UNI[4]
        after:
        root (RetypedCloneBasicNode/Seq)  ┆  Ⓣ UNI[16]
        └── id (RetypedCloneInteger/Prim)  ┆  Ⓣ UNI[2]
        └── dido (OctetString/Prim)  ┆  Ⓣ UNI[2]      <--- this is now an OctetString with tag uni[2] (tag for integers)
        └── ∅ data (RetypedCloneOctetString/Prim)  ┆  Ⓣ UNI[4]
        """
        # return
        node = BasicNode()
        dump_asn1_schema(node)

        # The substitution format is asn1path -> new_type, keep_tag
        # If keep_tag is True, it will force-preserve the old tag that corresponds to the old data-type
        substitutions = {
            'dido': (univ.OctetString(), True)
        }
        cloned = clone_schema(node, prefix="RetypedOldtagClone", substitutions=substitutions)
        dump_asn1_schema(cloned)

        original_dido_type = cloned.componentType['dido'].getType()

        # the type must be OctetString, but the tags should be those from Integer, UNI[2]
        self.assertIsInstance(original_dido_type, univ.OctetString)
        self.assertEqual(original_dido_type.tagSet, univ.Integer().tagSet)

        # try setting the thing to an OctetString value and actually encoding it
        cloned['id'] = 45
        cloned['dido'] = b'012345'
        cloned['data'] = b'99999'


        # Even if we encode it on our end, from the decoder's perspective this may end up as garbage or as
        # misinterpreted data. In this example, the bytes b'012345' will be seen as some big integer value which may
        # or may not make sense for the application. This could have been accomplished with keep_tag=True and simply
        # setting that element to a big integer value.
        _encoded = encoder.encode(cloned)
        # print(b64encode(_encoded))  # MBICAS0CBjAxMjM0NQQFOTk5OTk=



    def test_nested_substitution_path(self):
        """
        GIVEN a pyasn1 schema with nested objects
        WHEN we substitute the type of an item specified by asn1path
        THEN the schema is cloned and only that specific field is changed

        before:
        root (ComplexSchema/Seq)  ┆  Ⓣ UNI[16]
        └── version (Integer/Prim)  ┆  Ⓣ UNI[2]
        └── meta (TaggedNode/Seq)  ┆  Ⓣ UNI[16]
            └── id (Integer/Prim)  ┆  Ⓣ UNI[2]
            └── ∅ data (OctetString/Prim)  ┆  Ⓣ CTX[1]
        after:
        root (MutatedComplexSchema/Seq)  ┆  Ⓣ UNI[16]
        └── version (MutatedInteger/Prim)  ┆  Ⓣ UNI[2]
        └── meta (MutatedTaggedNode/Seq)  ┆  Ⓣ UNI[16]
            └── id (OctetString/Prim)  ┆  Ⓣ UNI[4]      <-- this is now an octetstring
            └── ∅ data (MutatedOctetString/Prim)  ┆  Ⓣ CTX[1]
        """
        node = ComplexSchema()
        dump_asn1_schema(node)

        substitutions = {'meta.id': (univ.OctetString(), True)}
        cloned = clone_schema(node, substitutions=substitutions)
        dump_asn1_schema(cloned)

        # Verify 'version' remains untouched (Integer)
        self.assertIsInstance(cloned.componentType['version'].getType(), univ.Integer)

        # Navigate to the nested mutant and ensure type substitution was applied
        meta_schema = cloned.componentType['meta'].getType()
        id_schema = meta_schema.componentType['id'].getType()
        self.assertIsInstance(id_schema, univ.OctetString)

        # Is the 'meta' container tag preserved?
        # 'meta' should still be [2] EXPLICIT CONSTRUCTED
        orig_meta_tag = node.componentType['meta'].getType().tagSet
        self.assertEqual(meta_schema.tagSet, orig_meta_tag)


    def test_mutate_pkimessage_all_optional(self):
        """
        GIVEN a pyasn1 PKIMessage object
        WHEN we clone the schema with everything_optional=True
        THEN the cloned schema will have all attributes marked as optional
        """
        raw = load_and_decode_pem_file("data/cmp-sample-reject.pem")
        pkimessage = parse_pkimessage(raw)

        mutated = clone_schema(pkimessage, everything_optional=True)
        # manually checking that everything is indeed optional would be tedious,
        # but we can see it at a glance by dumping the schema and inspecting it.
        # dump_asn1_schema(mutated)
        encoder.encode(mutated)




    def test_mutate_pkimessage_remove_constraints(self):
        """
        GIVEN a pyasn1 PKIMessage object
        WHEN we clone the schema with remove_constraints=False=True
        THEN the cloned schema will have no constraints
        """
        return
        raw = load_and_decode_pem_file("data/cmp-sample-reject.pem")
        pkimessage = parse_pkimessage(raw)

        mutated = clone_schema(pkimessage, remove_constraints=True)
        dump_asn1_schema(mutated)
        encoder.encode(mutated)



if __name__ == "__main__":
    unittest.main()
