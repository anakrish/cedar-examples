use cedar_benchmarks::CedarOptEngine;
use cedar_benchmarks::{
    CedarEngine, Engine, ExampleApp, HierarchyStats, MultiExecutionReport, OpenFgaEngine,
    RandomBytes, RegoEngine, RegorusBackend, RegorusEngine,
};
use cedar_policy_core::ast::Request;
use cedar_policy_core::entities::{Entities, EntityJson, TCComputation};
use cedar_policy_core::extensions::Extensions;
use cedar_policy_core::validator::CoreSchema;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run benchmarks
    Bench(BenchArgs),
}

#[derive(Args, Debug)]
pub struct BenchArgs {
    #[clap(flatten)]
    common_args: CommonBenchArgs,

    /// Number of bytes to use for `Unstructured`
    ///
    /// To run multiple experiments, use comma-separated values.
    /// E.g., `--unstructured-bytes 1024,2048,4096` runs three experiments, one
    /// with each of the values, and generates plots accordingly.
    #[arg(short, long, value_delimiter = ',', default_value = "8192")]
    unstructured_bytes: Vec<usize>,

    /// Number of entities to generate, per entity type.
    /// E.g., `--num-entities 3` generates a hierarchy with three entities per entity type.
    ///
    /// To run multiple experiments, use comma-separated values.
    /// E.g., `--num-entities 3,4,5` runs three experiments, one with each of the
    /// values of the num-entities parameter, and generates plots accordingly.
    #[arg(long, value_delimiter = ',', default_value = "3")]
    num_entities: Vec<usize>,

    /// Directory for CSVs and plots
    #[arg(long, default_value = "output")]
    output_dir: PathBuf,
}

/// Parameters which we don't experimentally vary
#[derive(Args, Debug)]
pub struct CommonBenchArgs {
    /// Which example application to benchmark
    ///
    /// To run multiple applications, use comma-separate values.
    /// E.g., `--app github,gdrive` runs all experiments with both the `github`
    /// and `gdrive` apps.
    #[arg(long, value_enum, value_delimiter = ',', required = true)]
    app: Vec<App>,

    /// Which authorization engine to test
    ///
    /// Comma-separated values are accepted.
    /// E.g., `--engine cedar,openfga` performs all tests both on Cedar and on
    /// OpenFGA.
    #[arg(long, value_enum, value_delimiter = ',', default_value = "cedar")]
    engine: Vec<EngineChoice>,

    /// Number of requests to generate, per hierarchy
    #[arg(short = 'r', long, default_value_t = 100)]
    num_requests: usize,

    /// Number of hierarchies to generate, per experiment.
    /// Each experiment will generate this many hierarchies, and `num-requests` requests per hierarchy.
    #[arg(short = 'n', long, default_value_t = 100)]
    num_hierarchies: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum, Hash)]
pub enum App {
    /// Github example application
    Github,
    /// Github example application, alternate templates encoding
    GithubTemplates,
    /// Gdrive example application
    Gdrive,
    /// Gdrive example application, alternate templates encoding
    GdriveTemplates,
    /// TinyTodo example application
    TinyTodo,
}

impl std::fmt::Display for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Github => write!(f, "github"),
            Self::GithubTemplates => write!(f, "github-templates"),
            Self::Gdrive => write!(f, "gdrive"),
            Self::GdriveTemplates => write!(f, "gdrive-templates"),
            Self::TinyTodo => write!(f, "tinytodo"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, ValueEnum)]
pub enum EngineChoice {
    /// Cedar authorization engine
    Cedar,
    /// OpenFGA authorization engine
    OpenFGA,
    /// Cedar with policy slicing
    CedarOpt,
    /// Rego authorization engine
    Rego,
    /// Rego authorization engine, pre-compute transitive closure
    RegoPreTC,
    /// Regorus interpreter with the fork's optimized policies
    Regorus,
    /// Regorus interpreter with precomputed entity transitive closure
    RegorusPreTC,
    /// Regorus compiled Rego virtual machine
    RegorusRvm,
    /// Regorus RVM with precomputed entity transitive closure
    RegorusRvmPreTC,
}

impl std::fmt::Display for EngineChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cedar => write!(f, "cedar"),
            Self::OpenFGA => write!(f, "openfga"),
            Self::CedarOpt => write!(f, "cedaropt"),
            Self::Rego => write!(f, "rego"),
            Self::RegoPreTC => write!(f, "rego_pre_tc"),
            Self::Regorus => write!(f, "regorus"),
            Self::RegorusPreTC => write!(f, "regorus_pre_tc"),
            Self::RegorusRvm => write!(f, "regorus_rvm"),
            Self::RegorusRvmPreTC => write!(f, "regorus_rvm_pre_tc"),
        }
    }
}

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Bench(args) => bench(args),
    }
}

/// Run a single experiment.
/// This involves generating potentially many hierarchies, and many requests per hierarchy,
/// but with constant num-entities and unstructured-bytes parameters.
fn run_experiment(
    app: App,
    num_entities: usize,
    unstructured_bytes: usize,
    common_args: &CommonBenchArgs,
    bytes: &mut RandomBytes,
) -> (HierarchyStats, BTreeMap<EngineChoice, MultiExecutionReport>) {
    eprintln!("Running experiment for {app} with {unstructured_bytes} unstructured bytes and {num_entities} entities per entity type...");
    let app = match app {
        App::Github => ExampleApp::github(&mut bytes.unstructured(unstructured_bytes)),
        App::GithubTemplates => {
            ExampleApp::github_templates(&mut bytes.unstructured(unstructured_bytes))
        }
        App::Gdrive => ExampleApp::gdrive(&mut bytes.unstructured(unstructured_bytes)),
        App::GdriveTemplates => {
            ExampleApp::gdrive_templates(&mut bytes.unstructured(unstructured_bytes))
        }
        App::TinyTodo => ExampleApp::tinytodo(&mut bytes.unstructured(unstructured_bytes)),
    };
    let mut hierarchy_stats = HierarchyStats::new();
    let mut multireports: BTreeMap<EngineChoice, MultiExecutionReport> = BTreeMap::new();
    (0..common_args.num_hierarchies).for_each(|hierarchy_index| {
        let (entities, links) = (app.bespoke_generator)(&app.validator_schema(), num_entities);
        let mut num_openfga_tuples = 0;
        let mut choices = common_args.engine.clone();
        let offset = hierarchy_index % choices.len();
        choices.rotate_left(offset);
        let engines = choices.iter().map(|choice| match choice {
            EngineChoice::Cedar => {
                let engine = CedarEngine::new(&entities, &links, &app);
                (choice, Engine::Cedar(engine))
            },
            EngineChoice::CedarOpt => {
                let engine = CedarOptEngine::new(&entities, &links, &app);
                (choice, Engine::CedarOpt(engine))
            }
            EngineChoice::OpenFGA => {
                let engine = OpenFgaEngine::new(&entities, links.clone(), &app);
                num_openfga_tuples = engine.num_tuples(); // overwrite the previous value. This means we'll only get the latest value but that's fine
                (choice, Engine::OpenFga(engine))
            },
            EngineChoice::Rego => {
                let engine = RegoEngine::new(&app, &entities);
                (choice, Engine::Rego(engine))
            },
            EngineChoice::RegoPreTC => {
                let engine = RegoEngine::new(&app, &entities);
                (choice, Engine::RegoTC(engine))
            }
            EngineChoice::Regorus | EngineChoice::RegorusRvm => {
                let backend = if *choice == EngineChoice::RegorusRvm {
                    RegorusBackend::Rvm
                } else {
                    RegorusBackend::Interpreter
                };
                (choice, Engine::Regorus(RegorusEngine::new(&app, &entities, backend)))
            }
            EngineChoice::RegorusPreTC | EngineChoice::RegorusRvmPreTC => {
                let backend = if *choice == EngineChoice::RegorusRvmPreTC {
                    RegorusBackend::Rvm
                } else {
                    RegorusBackend::Interpreter
                };
                (choice, Engine::RegorusTC(RegorusEngine::new(&app, &entities, backend)))
            }
        });
        let cedar_entities = Entities::from_entities(
            entities.clone(),
            Some(&CoreSchema::new(&app.validator_schema())),
            TCComputation::ComputeNow,
            Extensions::all_available(),
        ).unwrap();
        let requests: Vec<Request> = {
            let mut vec = Vec::with_capacity(common_args.num_requests);
            let u = &mut bytes.unstructured(unstructured_bytes);
            let hierarchy = cedar_entities.clone().into();
            let mut generate_request = || {
                app.schema
                    .arbitrary_request(&hierarchy, u)
                    .expect("failed to generate request")
                    .into()
            };
            vec.resize_with(common_args.num_requests, || {
                // `arbitrary_request()` intentionally sometimes generates requests with nonexistent
                // principal and/or resource.
                // We don't want that behavior here, but rather than change the behavior of the
                // request generator, we just keep calling it until we get one we want.
                loop {
                    let request: Request = generate_request();
                    if hierarchy.uids().any(|h_uid| request.principal().uid() == Some(h_uid))
                        && hierarchy.uids().any(|h_uid| request.resource().uid() == Some(h_uid))
                        {
                            break request;
                        }
                }
            });
            vec
        };
        // The "decision sequence" of each engine is the allow/deny sequence, which we assert needs to be the same for each engine else we're doing something wrong. (The engines should have the same allow/deny behavior.)
        let mut decision_sequences: Vec<(EngineChoice, Vec<_>)> = Vec::new();
        for (choice, engine) in engines {
            let mreport = multireports.entry(*choice).or_insert_with(MultiExecutionReport::new);
            decision_sequences.push((*choice, Vec::with_capacity(requests.len())));
            let (_, decision_sequence) = decision_sequences.last_mut().expect("just pushed, so there should be a last element");
            let reports: Vec<_> = engine.execute(requests.clone()).collect();
            for sreport in reports {
                decision_sequence.push(sreport.decision);
                mreport.add(sreport);
            }
            if matches!(choice, EngineChoice::Rego | EngineChoice::RegoPreTC)
                && matches!(app.name, "github-templates" | "gdrive-templates")
            {
                // The OPA harness warns and intentionally skips template encodings.
                assert!(decision_sequence.is_empty());
                decision_sequences.pop();
            } else {
                assert_eq!(decision_sequence.len(), requests.len(), "{choice} did not evaluate every request");
            }
        }
        let report_decision_mismatch = |request, engine_1, decision_1, engine_2, decision_2| {
            let entities: Vec<EntityJson> = entities.iter().map(|e| EntityJson::from_entity(e).unwrap()).collect();
            serde_json::to_writer_pretty(std::io::stderr(), &entities).unwrap();
            panic!("Decision mismatch for {request}: {engine_1} gave {decision_1:?} but {engine_2} gave {decision_2:?}");
        };
        if let Some((reference_engine, reference)) = decision_sequences.first() {
            for (choice, decisions) in decision_sequences.iter().skip(1) {
                for ((request, expected), actual) in requests.iter().zip(reference).zip(decisions) {
                    if expected != actual {
                        report_decision_mismatch(request, *reference_engine, expected, *choice, actual);
                    }
                }
            }
        }
        hierarchy_stats.add(&cedar_entities, num_openfga_tuples);
    });
    //multireport.print(&mut std::io::stderr()).unwrap();
    (hierarchy_stats, multireports)
}

fn bench(args: BenchArgs) {
    let common_args = &args.common_args;
    let num_entities = &args.num_entities;
    let unstructured_bytes = &args.unstructured_bytes[..];
    std::fs::create_dir_all(&args.output_dir).expect("failed to create output directory");
    let manifest_path = args.output_dir.join("run-manifest.json");
    assert!(
        !manifest_path.exists(),
        "use a fresh output directory; a run manifest already exists"
    );
    for app in App::value_variants() {
        assert!(
            !args.output_dir.join(format!("{app}.csv")).exists(),
            "use a fresh output directory; {app}.csv already exists"
        );
    }
    let mut manifest = serde_json::json!({
        "apps": common_args.app.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "engines": common_args.engine.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "num_entities": num_entities,
        "unstructured_bytes": unstructured_bytes,
        "num_hierarchies": common_args.num_hierarchies,
        "num_requests": common_args.num_requests,
        "warmup": "one request per Cedar/Regorus instance, excluded",
        "engine_order": "rotated by hierarchy index",
        "quantiles": "exact empirical, linear interpolation at q*(n-1)",
        "source_sha256": std::env::var("BENCHMARK_SOURCE_SHA256").ok(),
        "complete": false,
    });
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .expect("failed to write run manifest");
    for app in &common_args.app {
        let mut multireports = num_entities
            .iter()
            .flat_map(move |num_entities| {
                let mut bytes = RandomBytes::new();
                unstructured_bytes.iter().map(move |unstructured_bytes| {
                    let (hstats, multireports) = run_experiment(
                        *app,
                        *num_entities,
                        *unstructured_bytes,
                        common_args,
                        &mut bytes,
                    );
                    (num_entities, unstructured_bytes, hstats, multireports)
                })
            })
            .peekable();
        let csv_filename = args.output_dir.join(format!("{app}.csv"));
        let mut csv = File::create(csv_filename).expect("failed to create output CSV");
        write!(&mut csv, "num_entities,unstructured_bytes,").unwrap();
        for choice in common_args.engine.iter() {
            MultiExecutionReport::csv_header(&mut csv, &choice.to_string()).unwrap();
            write!(&mut csv, ",").unwrap();
        }
        {
            // to write the hierarchy stats portion of the header we need a concrete `HierarchyStats` object,
            // so we just use the first one and assume it's representative
            let Some((_, _, hstats, _)) = multireports.peek() else {
                eprintln!("this combination of args resulted in no experiments to run");
                return;
            };
            hstats.csv_header(&mut csv).unwrap();
        }
        writeln!(&mut csv).unwrap();
        for (num_entities, unstructured_bytes, hierarchy_stats, multireports) in multireports {
            write!(&mut csv, "{num_entities},{unstructured_bytes},").unwrap();
            for engine in &common_args.engine {
                let multireport = multireports.get(engine).unwrap();
                multireport.csv_row(&mut csv).unwrap();
                write!(&mut csv, ",").unwrap();
            }
            hierarchy_stats.csv_row(&mut csv).unwrap();
            writeln!(&mut csv).unwrap();
        }
    }
    manifest["complete"] = true.into();
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .expect("failed to complete run manifest");
    eprintln!("generating plot(s)...");
    let status = Command::new("python3")
        .arg("./plot.py")
        .arg(&args.output_dir)
        .status()
        .expect("failed to start plot.py");
    assert!(status.success(), "plot generation failed: {status}");
    eprintln!("Done")
}
