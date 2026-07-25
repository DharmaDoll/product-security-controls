#!/usr/bin/env bash
set -euo pipefail

mkdir -p generated/mappings

ruby <<'RUBY'
require "yaml"
require "fileutils"

controls = Dir["controls/*/*/control.yaml"].sort.map do |path|
  data = YAML.load_file(path)
  data.merge("_path" => path)
end

by_framework = Hash.new { |hash, key| hash[key] = [] }

controls.each do |control|
  Array(control["mappings"]).each do |mapping|
    by_framework[mapping.fetch("framework")] << {
      "control_id" => control.fetch("id"),
      "title" => control.fetch("title"),
      "path" => control.fetch("_path"),
      "mapping" => mapping
    }
  end
end

by_framework.each do |framework, rows|
  out = +"# #{framework} mappings\n\n"
  out << "| Control | Framework version | Identifier | Relationship | Confidence | Rationale |\n"
  out << "| --- | --- | --- | --- | --- | --- |\n"

  rows.sort_by { |row| [row["mapping"].fetch("id"), row["control_id"]] }.each do |row|
    mapping = row.fetch("mapping")
    control = "#{row.fetch("control_id")} - #{row.fetch("title")}"
    out << "| #{control} | #{mapping.fetch("version")} | #{mapping.fetch("id")} | "
    out << "#{mapping.fetch("relationship")} | #{mapping.fetch("confidence")} | "
    out << "#{mapping.fetch("rationale").to_s.gsub("\n", " ")} |\n"
  end

  File.write("generated/mappings/#{framework}.md", out)
end

puts "generated #{by_framework.length} framework mapping index files"
RUBY
