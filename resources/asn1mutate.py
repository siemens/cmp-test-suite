from pyasn1.type import univ, namedtype, constraint, tag

from pyasn1.type import constraint, namedtype


def clone_schema(obj, prefix="Mutated", remove_constraints=False,
                 everything_optional=False, substitutions=None, current_path=""):
    substitutions = substitutions or {}
    original_cls = obj.__class__
    new_class_name = f"{prefix}{original_cls.__name__}"

    new_components = None
    if hasattr(obj, 'componentType'):
        orig_ct = obj.componentType
        if isinstance(orig_ct, namedtype.NamedTypes):
            temp_components = []
            for i in range(len(orig_ct)):
                nt = orig_ct[i]
                name = nt.getName()

                # Construct the full asn1path for this component
                path = f"{current_path}.{name}" if current_path else name


                if path in substitutions:  # Path-based match found
                    new_type, keep_tag = substitutions[path]
                    if keep_tag:
                        cloned_inner = new_type.clone(tagSet=nt.getType().tagSet)  # change type, keep old tags
                    else:
                        cloned_inner = new_type.clone()  # change type, update tags

                else:
                    # Recurse, passing the current path deeper
                    cloned_inner = clone_schema(
                        nt.getType(), prefix, remove_constraints,
                        everything_optional, substitutions, path
                    )

                target_cls = namedtype.OptionalNamedType if everything_optional else nt.__class__
                temp_components.append(target_cls(name, cloned_inner))
            new_components = namedtype.NamedTypes(*temp_components)

        # Handle SequenceOf/SetOf (path remains the same for elements)
        elif orig_ct is not None:
            new_components = clone_schema(
                orig_ct, prefix, remove_constraints,
                everything_optional, substitutions, current_path
            )

    MutantClass = type(new_class_name, (original_cls,), {
        'componentType': new_components,
        'tagSet': obj.tagSet
    })

    return MutantClass()


def project_values(source, target):
    """
    Recursively copies values from source to target.
    """
    # Base Case: If source is a primitive leaf
    if not hasattr(source, 'componentType') or source.componentType is None:
        return source  # Return the value to be set by the parent

    # Recursive Case: Source is a container
    if isinstance(source, (univ.Sequence, univ.Set, univ.Choice)):
        for name in source:
            if not source.getComponentByName(name).isValue:
                continue

            source_item = source.getComponentByName(name)
            target_item = target.getComponentByName(name)

            if hasattr(source_item, 'componentType') and source_item.componentType is not None:
                # Recurse into nested constructed types
                project_values(source_item, target_item)
            else:
                # Direct assignment for primitives
                target.setComponentByName(name, source_item)

    elif isinstance(source, (univ.SequenceOf, univ.SetOf)):
        for i in range(len(source)):
            # Ensure target has enough slots
            if len(target) <= i:
                target.setComponentByPosition(i, target.getComponentType().clone())
            project_values(source[i], target[i])

    return target