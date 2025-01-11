# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
# setup for liboqs, if one wants to run it on its own machine.
sudo apt update
sudo apt install libssl-dev
sudo apt install cmake
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .
cd ..


