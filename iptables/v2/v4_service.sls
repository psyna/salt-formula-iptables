{% from "iptables/map.jinja" import defaults, service, schema with context %}

{%- if service.v4.enabled %}

iptables_packages_v4:
  pkg.installed:
  - names: {{ service.v4.pkgs }}

iptables_modules_v4_load:
  kmod.present:
  - persist: true
  - mods: {{ service.v4.modules }}
  - require:
    - pkg: iptables_packages_v4

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

{{ service.v4.persistent_config }}:
  file.managed:
  - user: root
  - group: root
  - mode: 640
  - require:
    - pkg: iptables_packages_v4

{% if grains['os'] == 'Ubuntu' %}
iptables_services_v4_start:
  cmd.run:
  - name: find /usr/share/netfilter-persistent/plugins.d/[0-9]*-ip4tables -exec {} start \;
  - onlyif: test $(iptables-save | wc -l) -eq 0
  - require:
    - file: {{ service.v4.persistent_config }}
    - kmod: iptables_modules_v4_load
{%- endif %}

{{ service.v4.service }}:
  service.running:
  - enable: true
  - require:
    - file: {{ service.v4.persistent_config }}
    - kmod: iptables_modules_v4_load
  - watch:
    - file: {{ service.v4.persistent_config }}
{%- endif %}