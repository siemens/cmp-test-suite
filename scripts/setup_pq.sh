# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
# setup for liboqs, if one wants to run it on its own machine.
sudo apt update
sudo apt install libssl-dev
sudo apt install cmake
git clone --depth=1 https://github.com/Guiliano99/liboqs-python-stateful-sig.git
# shellcheck disable=SC2164
cd liboqs-python-stateful-sig
pip install .
# shellcheck disable=SC2103
cd ..
# sanity check, if an error occurs, the script will try to install itself,
# which resolves the problem.
python liboqs-python-stateful-sig/examples/kem.py
