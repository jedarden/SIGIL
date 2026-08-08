use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};

#[derive(Debug, Clone)]
struct UnusedImportWarning {
    import_path: String,
    file_path: String,
    line: u32,
    column: u32,
}

fn parse_clippy_output(output_file: &str) -> Vec<UnusedImportWarning> {
    let file = File::open(output_file).expect("Failed to open clippy output file");
    let reader = BufReader::new(file);

    let mut warnings = Vec::new();
    let mut current_import: Option<String> = None;
    let mut current_file: Option<String> = None;
    let mut current_line: Option<u32> = None;
    let mut current_column: Option<u32> = None;

    for line in reader.lines() {
        let line = line.expect("Failed to read line");

        // Match the warning line: "warning: unused import: `import_path`"
        if line.contains("warning: unused import:") {
            if let Some(start) = line.find('`') {
                if let Some(end) = line.rfind('`') {
                    current_import = Some(line[start + 1..end].to_string());
                }
            }
        }
        // Match the location line: "--> file:line:column"
        else if line.contains("-->") && current_import.is_some() {
            let location = line.split("-->").nth(1).unwrap_or("");
            let parts: Vec<&str> = location.trim().split(':').collect();

            if parts.len() >= 3 {
                current_file = Some(parts[0].to_string());
                current_line = parts[1].parse().ok();
                current_column = parts[2].parse().ok();
            }
        }
        // When we have all components, create the warning
        else if line.trim().is_empty() || line.starts_with("|") {
            if let (Some(import), Some(file), Some(line), Some(col)) =
                (current_import.take(), current_file.take(), current_line.take(), current_column.take()) {
                warnings.push(UnusedImportWarning {
                    import_path: import,
                    file_path: file,
                    line,
                    column: col,
                });
            }
        }
    }

    // Handle the last warning if file doesn't end with empty line
    if let (Some(import), Some(file), Some(line), Some(col)) =
        (current_import, current_file, current_line, current_column) {
        warnings.push(UnusedImportWarning {
            import_path: import,
            file_path: file,
            line,
            column: col,
        });
    }

    warnings
}

fn group_warnings_by_file(warnings: &[UnusedImportWarning]) -> HashMap<String, Vec<&UnusedImportWarning>> {
    let mut grouped: HashMap<String, Vec<&UnusedImportWarning>> = HashMap::new();

    for warning in warnings {
        grouped.entry(warning.file_path.clone())
            .or_insert_with(Vec::new)
            .push(warning);
    }

    grouped
}

fn generate_report(warnings: &[UnusedImportWarning]) -> String {
    let grouped = group_warnings_by_file(warnings);
    let mut report = String::new();

    report.push_str("# Unused Import Warnings Report\n\n");
    report.push_str(&format!("Total unused imports found: {}\n\n", warnings.len()));

    let mut sorted_files: Vec<_> = grouped.iter().collect();
    sorted_files.sort_by_key(|(k, _)| *k);

    for (file, file_warnings) in sorted_files {
        report.push_str(&format!("## File: {}\n", file));
        report.push_str(&format!("Found {} unused import(s):\n\n", file_warnings.len()));

        for warning in file_warnings {
            report.push_str(&format!(
                "- Line {}, Col {}: `{}`\n",
                warning.line, warning.column, warning.import_path
            ));
        }
        report.push_str("\n");
    }

    // Summary section
    report.push_str("---\n\n## Summary\n\n");
    report.push_str("### File Count\n");
    report.push_str(&format!("- Files with unused imports: {}\n", grouped.len()));

    report.push_str("\n### All Unused Imports\n");
    for warning in warnings {
        report.push_str(&format!("- `{}` in {}:{}:{}\n",
            warning.import_path,
            warning.file_path,
            warning.line,
            warning.column
        ));
    }

    report
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <clippy_output_file> [output_report_file]", args[0]);
        std::process::exit(1);
    }

    let input_file = &args[1];
    let output_file = if args.len() > 2 { &args[2] } else { "unused_imports_report.md" };

    println!("Parsing clippy output from: {}", input_file);
    let warnings = parse_clippy_output(input_file);

    println!("Found {} unused import warnings", warnings.len());

    let report = generate_report(&warnings);

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_file)
        .expect("Failed to create output file");

    file.write_all(report.as_bytes()).expect("Failed to write report");

    println!("Report written to: {}", output_file);

    // Print summary to stdout
    println!("\n--- Summary ---");
    let grouped = group_warnings_by_file(&warnings);
    println!("Files affected: {}", grouped.len());

    let mut sorted_files: Vec<_> = grouped.iter().collect();
    sorted_files.sort_by_key(|(k, _)| *k);

    for (file, file_warnings) in sorted_files {
        println!("  - {}: {} unused import(s)", file, file_warnings.len());
    }
}