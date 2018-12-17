{% from "iptables/map.jinja" import defaults, service, schema with context %}

{%- if service.v6.enabled %}

{%- if salt.service.available('docker') %}
{{ service.v4.persistent_config }}.salt-v6:
  file.managed:
    - contents: |
      {%- for line in salt.iptables_v2.with_docker_rules().splitlines() %}
        {{ line }}
      {%- endfor %}
{%- else %}
{{ service.v4.persistent_config }}.salt-v6:
  file.managed:
    - contents: |
      {%- for line in salt.iptables_v2.pillar_rules().splitlines() %}
        {{ line }}
      {%- endfor %}
{%- endif %}

restore-iptables-v6:
  cmd.run:
    - name: iptables-restore < {{ service.v4.persistent_config }}.salt-v6
    - onchanges:
        - file: {{ service.v4.persistent_config }}.salt-v6

{%- if salt.iptables_v2.current_saved_diff() %}
renew-iptables-v6:
  cmd.run:
    - name: iptables-save > {{ service.v6.persistent_config }}
    - order: last
{%- endif %}

{%- endif %}
