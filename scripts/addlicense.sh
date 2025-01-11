#!/bin/bash
# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

# Add SPDX license identifier to all Python files that don't have it.


header="# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
"

# Find all .py files in the current directory and its subdirectories
find ./ -type f -name "*.py" | while read -r file; do
    # Check if the file already contains the SPDX-License-Identifier
    if ! grep -q "SPDX-License-Identifier:" "$file"; then
        # If not, add the header at the beginning of the file
        echo -e "$header\n$(cat "$file")" > "$file"
        echo "Header added to $file"
    else
        echo "Header already exists in $file"
    fi
done
