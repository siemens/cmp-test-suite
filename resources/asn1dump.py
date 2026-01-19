# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Dump ASN1 schemas for quick and easy inspection.

ASN1 schemas can get very complex, this module produces a concise human-readable representation that helps understand
what you're looking at, at a glance. Unicode and colors are leveraged to prettify outputs.

The output is designed to be compact and convey useful information in a single line; but if multiple constraints or
details are there, the information will be broken down into several lines, for better readability.


Legend:
≡    named values, e.g. `≡ cmp1999(1), cmp2000(2), cmp2021(3)`
§    constraints (think of it as of a paragraph in a law that defines how something must be)
Ⓣ    tag information
∅    optional element

This is an excerpt of the PKIMessage schema that demonstrates this in action:

root (PKIMessageTMP/Seq)  ┆  Ⓣ UNI[16]
└── header (PKIHeader/Seq)  ┆  Ⓣ UNI[16]
    └── pvno (Integer/Prim)  ┆  Ⓣ UNI[2]  ┆  ≡ cmp1999(1), cmp2000(2), cmp2021(3)
    └── sender (GeneralName/Set)  ┆  § Size =1
        └── otherName (AnotherName/Seq)  ┆  Ⓣ CTX[0]
            └── type-id (ObjectIdentifier/Prim)  ┆  Ⓣ UNI[6]
            └── value (Any/Prim)  ┆  Ⓣ CTX[0]
        └── rfc822Name (IA5String/Prim)  ┆  Ⓣ CTX[1]
        └── dNSName (IA5String/Prim)  ┆  Ⓣ CTX[2]
        └── x400Address (ORAddress/Seq)  ┆  Ⓣ CTX[3]
            └── built-in-standard-attributes (BuiltInStandardAttributes/Seq)  ┆  Ⓣ UNI[16]
                └── ∅ country-name (CountryName/Set)  ┆  Ⓣ APP[1]  ┆  § Size =1
                └── ∅ administration-domain-name (AdministrationDomainName/Set)
                    ┆ Ⓣ APP[2]
                    ┆ § Size =1
                └── ∅ network-address (NetworkAddress/Prim)  ┆  Ⓣ CTX[0]  ┆  § Size [1..16]
                └── ∅ terminal-identifier (TerminalIdentifier/Prim)  ┆  Ⓣ CTX[1]  ┆  § Size [1..24]
                └── ∅ private-domain-name (PrivateDomainName/Set)  ┆  Ⓣ CTX[2]  ┆  § Size =1

The implementation is tied to pyasn1's internals and may break if pyasn1 undergoes major changes.
"""

# ruff: noqa: T201
# T201 - we directly print instead of returning strings and printing the final result once, because some data
#        structures can be deeply nested, recursion is involved - if a crash occurs, one can still see what
#        happened before that. For a debugging tool, this is sufficient.

import sys

from pyasn1.type import constraint, namedtype, tag, univ


class ASN1Styler:
    """Color schemes and primitives for colorized terminal output"""

    def __init__(self, use_color=True):
        """Define colors; if use_color is False, output will be monochrome"""
        # Detect TTY or respect flag
        self.enabled = use_color and sys.stdout.isatty()

        # Color Map
        self.C_DIM = '\033[90m' if self.enabled else ''
        self.C_BLUE = '\033[34m' if self.enabled else ''
        self.C_GOLD = '\033[33m' if self.enabled else ''
        self.C_GREEN = '\033[32m' if self.enabled else ''
        self.C_RESET = '\033[0m' if self.enabled else ''

    def dim(self, text):
        """Write a dim, slightly darker text"""
        return f"{self.C_DIM}{text}{self.C_RESET}"

    def name(self, text, is_optional):
        """Write a class name, make it dim and mark it as optional"""
        if is_optional:
            return f"{self.C_DIM}∅ {text}{self.C_RESET}"
        return text

    def type_block(self, cls_name, base_type):
        """Write the type, make it dim"""
        return self.dim(f"({cls_name}/{base_type})")

    def tag(self, text):
        """Write the tag"""
        return f"{self.C_BLUE}{text}{self.C_RESET}"

    def constraint(self, text):
        """Write a constraint that applies to ASN1 structures"""
        return f"{self.C_GOLD}§ {text}{self.C_RESET}"

    def label(self, text):
        """Write the named variables defined for an ASN1 attribute"""
        return f"{self.C_GREEN}≡ {text}{self.C_RESET}"

    def connector(self):
        """Draw a branch"""
        return self.dim("└── ")

    def v_line(self):
        """Draw a separator for various properties of an entry"""
        return self.dim("┆")

def get_tag_info(obj):
    """Extract all tag info in the order base tag, super tag1, super tag2....

    Example: "Ⓣ UNI/2p+CTX/0c" to be interpreted left-to-right as
    - the base tag is Universal 2, primitive; contains actual data
    - followed by Context 0, constructed; contains other TLVs
    """
    tag_set = obj.tagSet
    if not tag_set:
        return ""

    class_map = {
        tag.tagClassUniversal: "UNI",
        tag.tagClassApplication: "APP",
        tag.tagClassContext: "CTX",
        tag.tagClassPrivate: "PRI"
    }

    layers = []
    # pyasn1 stores BaseTag at 0, subsequently added tags follow:
    for t in tag_set:
        t_class = class_map.get(t.tagClass, "???")
        # bit 6: 0 = primitive, 32 = constructed
        t_fmt = "c" if t.tagFormat == 32 else "p"
        layers.append(f"{t_class}/{t.tagId}{t_fmt}")

    return f"Ⓣ {'+'.join(layers)}"


def parse_constraints(c_obj, is_coll=False):
    """Recursively inspect pyasn1 constraint objects.

    :param c_obj: pyasn1 constraint object
    :param is_coll: bool, flag that defines whether it is a collection of other objects
    """
    if not c_obj:
        return ""

    # If it is a collection, then we say "Count" to indicate how many items it may contain. We use "Size" for things
    # like OctetString, where you have just one item that can vary in size.
    label = "Count" if is_coll else "Size"

    # Size Constraints
    if isinstance(c_obj, constraint.ValueSizeConstraint):
        s1, s2 = str(c_obj.start), str(c_obj.stop).replace('inf', '∞')  # type: ignore
        if s1 == s2:
            return f"{label} ={s1}"
        if s2 == '∞':
            return f"{label} ≥{s1}"
        return f"{label} [{s1}..{s2}]"

    # Value Range (Integers)
    if isinstance(c_obj, constraint.ValueRangeConstraint):
        return f"Range [{str(c_obj.start)}..{str(c_obj.stop).replace('inf', '∞')}]"  # type: ignore

    # Single Value / Allowed
    if isinstance(c_obj, constraint.SingleValueConstraint):
        vals = ", ".join([str(v) for v in c_obj])
        return f"Allowed {vals}"

    # Intersections and unions of constraints
    if isinstance(c_obj, (constraint.ConstraintsIntersection, constraint.ConstraintsUnion)):
        op = " & " if isinstance(c_obj, constraint.ConstraintsIntersection) else " | "
        parts = [parse_constraints(inner, is_coll) for inner in c_obj]
        return op.join(filter(None, parts))

    return ""


def get_metadata(obj, verbosity, s: ASN1Styler):
    """Retrieve metadata of pyasn1 objects

    There are 3 verbosity levels
    1 - no metadata shown
    2 - get named values
    3 - as above + include information about constraints
    """
    meta = []
    is_coll = isinstance(obj, (univ.SequenceOf, univ.SetOf))

    if verbosity >= 2:
        t_info = get_tag_info(obj)
        if t_info:
            meta.append(s.tag(t_info))

        if hasattr(obj, 'namedValues') and obj.namedValues:
            nv = [f"{v}({n})" for v, n in obj.namedValues.items()]
            meta.append(s.label(f"{', '.join(nv[:5])}{'…' if len(nv) > 5 else ''}"))

    if verbosity >= 3 and hasattr(obj, 'subtypeSpec') and obj.subtypeSpec:
        c_text = parse_constraints(obj.subtypeSpec, is_coll)
        if c_text:
            meta.append(s.constraint(c_text))

    return meta


def dump_asn1_schema(obj, indent="", name="root", depth=0, max_depth=3,
                     verbosity=3, parent=None, styler=None, max_line_len=200):
    """Write the ASN1 schema of a pyasn1 object in a concise way

    :param obj: pyasn1 object to dump
    :param indent: str, indentation to use, needed when diving into nested objects
    :param name: str, name of the object type
    :param depth: int, depth at which we are right now, used for recursion
    :param max_depth: int, maximum depth of recursion
    :param verbosity: int, how much detail to include (see get_metadata)
    :param parent: pyasn1 object
    :param styler: Asn1Styler, defines whether the output is colorized
    :param max_line_len: int, maximum line length, beyond which metadata will be written in a separate line
    """
    if depth > max_depth:
        return

    # Initialize styler once at root object
    s = styler or ASN1Styler(use_color=True)

    # Determine if the object is optional and whether it has a default value. Perhaps this can be accomplished in a
    # better way, but so far this is done by getting the parent of "this" and extracting "this" through the parent.
    is_optional = False
    if parent is not None:
        ct = getattr(parent, 'componentType', None)
        if ct is not None and isinstance(ct, namedtype.NamedTypes):
            nt = ct[ct.getPositionByName(name)]
            is_optional = nt.isOptional or nt.isDefaulted

    # Get the base type
    type_name = obj.__class__.__name__
    base_type = "Prim"
    if isinstance(obj, univ.Sequence):
        base_type = "Seq"
    elif isinstance(obj, univ.Set):
        base_type = "Set"
    elif isinstance(obj, univ.Choice):
        base_type = "Choice"
    elif isinstance(obj, univ.SequenceOf):
        base_type = "SeqOf"
    elif isinstance(obj, univ.SetOf):
        base_type = "SetOf"

    conn = s.connector() if depth > 0 else ""
    line = f"{indent}{conn}{s.name(name, is_optional)} {s.type_block(type_name, base_type)}"

    # Sometimes there can be many named values and constraints that apply to a type. We try to squeeze everything in
    # a single line (if it fits under max_line_len), otherwise take multiple lines.
    meta_items = get_metadata(obj, verbosity, s)
    v_sep = f"  {s.v_line()}  "

    if meta_items and len(line + " ".join(meta_items)) < max_line_len:
        print(f"{line}{v_sep}{v_sep.join(meta_items)}")
    else:
        print(line)
        for item in meta_items:
            print(f"{indent}{'    ' if depth > 0 else ''}{s.v_line()} {item}")

    # Recurse and do the same for child items
    new_indent = indent + ("    " if depth > 0 else "")
    if hasattr(obj, 'componentType'):
        ct = obj.componentType
        if isinstance(ct, namedtype.NamedTypes):
            for i in range(len(ct)):
                # Pass 'obj' as parent to detect optionality in next turn
                dump_asn1_schema(ct[i].getType(), new_indent, ct.getNameByPosition(i),
                                 depth + 1, max_depth, verbosity, parent=obj, styler=s, max_line_len=max_line_len)
        elif ct is not None:
            dump_asn1_schema(ct, new_indent, "item", depth + 1, max_depth, verbosity, parent=obj,
                             styler=s, max_line_len=max_line_len)
