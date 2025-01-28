import pandas as pd

from pq_logic.hybrid_key_factory import HybridKeyFactory
from pq_logic.pq_key_factory import PQKeyFactory
from resources.keyutils import generate_key




df_pq = pd.DataFrame(columns=["name", "public_key_size", "private_key_size", "ct_length", "claimed_nist_level"])
df_hybrid = pd.DataFrame(columns=["name", "public_key_size", "private_key_size", "ct_length"])

pq_data = []

for alg_name in PQKeyFactory.get_all_kem_alg():
    key = generate_key(algorithm=alg_name)
    pq_data.append({"name": key.name, "public_key_size": key.public_key().key_size,
                    "private_key_size": key.key_size,
                    "ct_length": key.ct_length,
                   "claimed_nist_level": key.claimed_nist_level})


hybrid_kem_mapping = {}

data = {}

for alg_name, options in HybridKeyFactory.get_all_kem_coms_as_dict().items():

    if alg_name not in data:
        data[alg_name] = []

    for methode in options:
        key = generate_key(algorithm=alg_name, **methode)
        entry = {"name": key.name, "public_key_size": key.public_key().key_size, "private_key_size": key.key_size, "ct_length": key.ct_length}
        data[alg_name].append(entry)

df_pq = pd.DataFrame(pq_data).sort_values(by="claimed_nist_level")

latex_pq = df_pq.to_latex(index=False)
latex_hybrid = df_hybrid.to_latex(index=False)

# Write LaTeX tables to files.
with open("./data/stats/pq_table.tex", "w") as f:
    f.write(latex_pq)

for alg_name, sublist in data.items():
    df_hybrid = pd.DataFrame(sublist)
    latex_hybrid = df_hybrid.to_latex(index=False)
    with open(f"./data/stats/hybrid_table_{alg_name}.tex", "w") as f:
        f.write(latex_hybrid)

from tabulate import tabulate

pq_str  = tabulate(pq_data, headers="keys", tablefmt="grid")
with open("./data/stats/pq_table.txt", "w") as f:
    f.write(pq_str)


for alg_name, sublist in data.items():
    hybrid_str = tabulate(sublist, headers="keys", tablefmt="grid")
    with open(f"./data/stats/hybrid_table_{alg_name}.txt", "w") as f:
        f.write(hybrid_str)



