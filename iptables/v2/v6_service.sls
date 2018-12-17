{% from "iptables/map.jinja" import defaults, service, schema with context %}

{%- if service.v6.enabled %}

iptables_packages_v6:
  pkg.installed:
  - names: {{ service.v6.pkgs }}

iptables_modules_v6_load:
  kmod.present:
  - persist: true
  - mods: {{ service.v6.modules }}
  - require:
    - pkg: iptables_packages_v6

{%- if salt.service.available('docker') %}
{{ service.v6.persistent_config }}.salt-v6:
  file.managed:
    - contents: |
      {%- for line in salt.iptables_v2.with_docker_rules().splitlines() %}
        {{ line }}
      {%- endfor %}
{%- else %}
{{ service.v6.persistent_config }}.salt-v6:
  file.managed:
    - contents: |
      {%- for line in salt.iptables_v2.pillar_rules().splitlines() %}
        {{ line }}
      {%- endfor %}
{%- endif %}

restore-iptables-v6:
  cmd.run:
    - name: ip6tables-restore < {{ service.v6.persistent_config }}.salt-v6
    - onchanges:
        - file: {{ service.v6.persistent_config }}.salt-v6

{%- if salt.iptables_v2.current_saved_diff() %}
renew-iptables-v6:
  cmd.run:
    - name: ip6tables-save > {{ service.v6.persistent_config }}
    - order: last
{%- endif %}

{{ service.v6.persistent_config }}:
  file.managed:
  - user: root
  - group: root
  - mode: 640
  - require:
    - pkg: iptables_packages_v6

{% if grains['os'] == 'Ubuntu' %}
iptables_services_v6_start:
  cmd.run:
  - name: find /usr/share/netfilter-persistent/plugins.d/[0-9]*-ip6tables -exec {} start \;
  - onlyif: test $(ip6tables-save | wc -l) -eq 0
  - require:
    - file: {{ service.v6.persistent_config }}
    - kmod: iptables_modules_v6_load
{%- endif %}

{{ service.v6.service }}:
  service.running:
  - enable: true
  - require:
    - file: {{ service.v6.persistent_config }}
    - kmod: ip6tables_modules_v6_load
  - watch:
    - file: {{ service.v6.persistent_config }}
{%- endif %}