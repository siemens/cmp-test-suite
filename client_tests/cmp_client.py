
from jinja2 import Template
from robot.api.deco import keyword

# Jinja2 templates for CMP CLI commands, define your template here
# This translates the tests in cmp_tests_jinja.robot to the actual commands that your CMP client will execute.
openssl = """
openssl cmp
 -cmd {{ cmd }}
 -server {{ server }}
 -subject {{ subject }}
 -secret {{ secret }}
 -ref {{ ref | default('NULL-DN') }}
{% if recipient %}-recipient {{ recipient }}{% endif %}
{% if csr %}-csr {{ csr }}{% endif %}
{% if newkey %}-newkey {{ newkey }}{% endif %}
{% if certout %}-certout {{ certout }}{% endif %}
{% if unprotected_requests %}-unprotected_requests{% endif %}
"""

gencmpclient = """
gencmpclient  {{ cmd }}
 --server {{ server }}
 --ref {{ ref }}
 --subject "{{ subject }}"
 --secret "{{ secret }}"
 {% if csr %}--csr {{ csr }}{% endif %}
 {% if newkey %}--newkey {{ newkey }}{% endif %}
 {% if certout %}--certout {{ certout }}{% endif %}
 
 """

embedded_cmp = """
./build/embedded_cmp
{% if cmd == "ir" %}-i{% endif %}
{% if cmd == "p10cr" or cmd == "cr" %}-c{% endif %}
{% if cmd == "kur" %}-k{% endif %}
"""


@keyword(name="Get CMP Command")
def get_cmp_command(client: str = "openssl", **kwargs) -> list:
    """Constructs a CMP command based on the client and keyword arguments.

    Arguments:
    ---------
    - `client`: The CMP client to use (e.g. "openssl").
    - `**kwargs`: Keyword arguments like cmd, server, ref, subject, etc.

    Returns:
    -------
    - List of command-line arguments suitable for use with Run Process

    Example:
    -------
    | ${args}= | Get CMP Command | openssl | cmd=ir | server=http://localhost:5000 | ... |

    """
    try:
        template = Template(globals()[client])
    except KeyError:
        raise ValueError(f"Unsupported CMP client: {client}")

    rendered = template.render(**kwargs)
    return rendered.strip().split()
