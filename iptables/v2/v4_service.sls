{% from "iptables/map.jinja" import defaults, service, schema with context %}

{%- if service.v4.enabled %}

{%- if salt.service.available('docker') %}
{{ service.v4.persistent_config }}.salt-v4:
  file.managed:
    - contents: |
      {%- for line in salt.iptables_v2.with_docker_rules().splitlines() %}
        {{ line }}
      {%- endfor %}
{%- else %}
{{ service.v4.persistent_config }}.salt-v4:
  file.managed:
    - contents: |
      {%- for line in salt.iptables_v2.pillar_rules().splitlines() %}
        {{ line }}
      {%- endfor %}
{%- endif %}

restore-iptables-v4:
  cmd.run:
    - name: iptables-restore < {{ service.v4.persistent_config }}.salt-v4
    - onchanges:
        - file: {{ service.v4.persistent_config }}.salt-v4

{%- if salt.iptables_v2.current_saved_diff() %}
renew-iptables-v4:
  cmd.run:
    - name: iptables-save > {{ service.v4.persistent_config }}
    - order: last
{%- endif %}

{%- endif %}