use cedar_benchmarks::CedarOptEngine;
use cedar_benchmarks::{
    CedarEngine, Engine, ExampleApp, HierarchyStats, MultiExecutionReport, OpenFgaEngine,
    RandomBytes, RegoCase, RegoEngine,
};
use cedar_policy_core::ast::Request;
use cedar_policy_core::entities::{Entities, EntityJson, TCComputation};
use cedar_policy_core::extensions::Extensions;
use cedar_policy_validator::CoreSchema;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::Command;

mod corpus;

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

    #[arg(long, conflicts_with = "replay_corpus")]
    record_corpus: Option<PathBuf>,

    #[arg(long)]
    replay_corpus: Option<PathBuf>,

    /// Fractional-microsecond samples and exact interpolated quantiles.
    #[arg(long)]
    precise_timing: bool,

    /// Save per-request durations and fail on authorization errors.
    #[arg(long)]
    raw_samples: bool,

    #[arg(long, default_value = "output")]
    output: PathBuf,
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
    /// Original Rego policies with native input conversion outside timing.
    RegoInputExcluded,
}

impl std::fmt::Display for EngineChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cedar => write!(f, "cedar"),
            Self::OpenFGA => write!(f, "openfga"),
            Self::CedarOpt => write!(f, "cedaropt"),
            Self::Rego => write!(f, "rego"),
            Self::RegoPreTC => write!(f, "rego_pre_tc"),
            Self::RegoInputExcluded => write!(f, "rego_input_excluded"),
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
    let app_name = app.to_string();
    let corpus_directory = common_args
        .record_corpus
        .as_ref()
        .or(common_args.replay_corpus.as_ref())
        .map(|root| root.join(&app_name).join(num_entities.to_string()));
    let schema_bytes = if common_args.replay_corpus.is_some() {
        let metadata: corpus::Metadata =
            corpus::read(&corpus_directory.as_ref().unwrap().join("metadata.json"));
        assert_eq!(metadata.format_version, 1, "unsupported corpus format");
        assert_eq!(metadata.app, app_name, "corpus app mismatch");
        assert_eq!(metadata.num_entities, num_entities, "corpus size mismatch");
        assert_eq!(
            metadata.num_hierarchies, common_args.num_hierarchies,
            "corpus hierarchy count mismatch"
        );
        assert_eq!(
            metadata.num_requests, common_args.num_requests,
            "corpus request count mismatch"
        );
        assert_eq!(
            metadata.schema_bytes.len(),
            unstructured_bytes,
            "corpus schema byte count mismatch"
        );
        metadata.schema_bytes
    } else {
        bytes.unstructured(unstructured_bytes).take_rest().to_vec()
    };
    if common_args.record_corpus.is_some() {
        let directory = corpus_directory.as_ref().unwrap();
        std::fs::create_dir_all(directory).expect("cannot create corpus directory");
        corpus::write(
            &directory.join("metadata.json"),
            &corpus::Metadata {
                format_version: 1,
                app: app_name.clone(),
                num_entities,
                num_hierarchies: common_args.num_hierarchies,
                num_requests: common_args.num_requests,
                schema_bytes: schema_bytes.clone(),
            },
        );
    }
    let mut schema_input = arbitrary::Unstructured::new(&schema_bytes);
    let app = match app {
        App::Github => ExampleApp::github(&mut schema_input),
        App::GithubTemplates => ExampleApp::github_templates(&mut schema_input),
        App::Gdrive => ExampleApp::gdrive(&mut schema_input),
        App::GdriveTemplates => ExampleApp::gdrive_templates(&mut schema_input),
        App::TinyTodo => ExampleApp::tinytodo(&mut schema_input),
    };
    let mut samples = common_args.raw_samples.then(|| {
        let path = common_args.output.join(format!(
            "{app_name}-{num_entities}-{unstructured_bytes}-samples.csv"
        ));
        let mut writer = BufWriter::new(
            File::options()
                .write(true)
                .create_new(true)
                .open(path)
                .expect("cannot create raw samples"),
        );
        writeln!(
            writer,
            "app,num_entities,hierarchy,engine,request,duration_ns,decision,errors"
        )
        .unwrap();
        writer
    });
    let mut hierarchy_stats = HierarchyStats::new();
    let mut multireports: BTreeMap<EngineChoice, MultiExecutionReport> = BTreeMap::new();
    (1..=common_args.num_hierarchies).for_each(|hierarchy_index| {
        let restored = common_args.replay_corpus.as_ref().map(|_| {
            let workload: corpus::Workload = corpus::read(
                &corpus_directory.as_ref().unwrap().join(format!("{hierarchy_index}.json")),
            );
            workload.restore(&CoreSchema::new(&app.validator_schema()))
        });
        let (entities, links, saved_requests) = if let Some((entities, links, requests)) = restored {
            assert_eq!(requests.len(), common_args.num_requests, "corpus request count mismatch");
            (entities, links, Some(requests))
        } else {
            let (entities, links) = (app.bespoke_generator)(&app.validator_schema(), num_entities);
            (entities, links, None)
        };
        let mut num_openfga_tuples = 0;
        let engines = common_args.engine.iter().map(|choice| match choice {
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
            EngineChoice::RegoInputExcluded => {
                let engine = RegoEngine::new(&app, &entities).with_case(RegoCase::InputExcluded);
                (choice, Engine::RegoInputExcluded(engine))
            }
        });
        let cedar_entities = Entities::from_entities(
            entities.clone(),
            Some(&CoreSchema::new(&app.validator_schema())),
            TCComputation::ComputeNow,
            Extensions::all_available(),
        ).unwrap();
        let requests: Vec<Request> = saved_requests.unwrap_or_else(|| {
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
                    if hierarchy.uids().iter().any(|h_uid| request.principal().uid() == Some(h_uid))
                        && hierarchy.uids().iter().any(|h_uid| request.resource().uid() == Some(h_uid))
                        {
                            break request;
                        }
                }
            });
            vec
        });
        if common_args.record_corpus.is_some() {
            corpus::write(
                &corpus_directory.as_ref().unwrap().join(format!("{hierarchy_index}.json")),
                &corpus::Workload::capture(&entities, &links, &requests),
            );
        }
        // The "decision sequence" of each engine is the allow/deny sequence, which we assert needs to be the same for each engine else we're doing something wrong. (The engines should have the same allow/deny behavior.)
        let mut decision_sequences: Vec<Vec<_>> = Vec::new();
        for (choice, engine) in engines {
            let mreport = multireports.entry(*choice).or_insert_with(|| {
                if common_args.precise_timing {
                    MultiExecutionReport::new_precise()
                } else {
                    MultiExecutionReport::new()
                }
            });
            decision_sequences.push(Vec::with_capacity(requests.len()));
            let decision_sequence = decision_sequences.last_mut().expect("just pushed, so there should be a last element");
            let mut raw = Vec::new();
            for (request_index, sreport) in engine.execute(requests.clone()).enumerate() {
                if samples.is_some() {
                    assert!(sreport.errors.is_empty(), "{app_name} {choice}: authorization errors: {:?}", sreport.errors);
                    raw.push((request_index, sreport.dur.as_nanos(), sreport.decision, sreport.errors.len()));
                }
                decision_sequence.push(sreport.decision);
                mreport.add(sreport);
            }
            assert_eq!(decision_sequence.len(), requests.len(), "{app_name} {choice}: missing decisions");
            if let Some(writer) = &mut samples {
                for (request_index, nanos, decision, errors) in raw {
                    writeln!(writer, "{app_name},{num_entities},{hierarchy_index},{choice},{request_index},{nanos},{decision:?},{errors}").unwrap();
                }
            }
        }
        let report_decision_mismatch = |request, engine_1, decision_1, engine_2, decision_2| {
            let entities: Vec<EntityJson> = entities.iter().map(|e| EntityJson::from_entity(e).unwrap()).collect();
            serde_json::to_writer_pretty(std::io::stderr(), &entities).unwrap();
            panic!("Decision mismatch for {request}: {engine_1} gave {decision_1:?} but {engine_2} gave {decision_2:?}");
        };
        match decision_sequences.len() {
            0 => panic!("expected at least 1 decision sequence"),
            1 => {} // nothing to do, only testing one engine
            2 => {
                for ((request, decision_1), decision_2) in requests.iter().zip(decision_sequences[0].iter()).zip(decision_sequences[1].iter()) {
                    if decision_1 != decision_2 {
                        report_decision_mismatch(request, common_args.engine[0], decision_1, common_args.engine[1], decision_2);
                    }
                }
            }
            3 => {
                for (((request, decision_1), decision_2), decision_3) in requests.iter().zip(decision_sequences[0].iter()).zip(decision_sequences[1].iter()).zip(decision_sequences[2].iter()) {
                    if decision_1 != decision_2 {
                        report_decision_mismatch(request, common_args.engine[0], decision_1, common_args.engine[1], decision_2);
                    } else if decision_1 != decision_3 {
                        report_decision_mismatch(request, common_args.engine[0], decision_1, common_args.engine[2], decision_3);
                    }
                }
            }
            4 => {
                for ((((request, decision_1), decision_2), decision_3), decision_4) in requests.iter().zip(decision_sequences[0].iter()).zip(decision_sequences[1].iter()).zip(decision_sequences[2].iter()).zip(decision_sequences[3].iter()) {
                    if decision_1 != decision_2 {
                        report_decision_mismatch(request, common_args.engine[0], decision_1, common_args.engine[1], decision_2);
                    } else if decision_1 != decision_3 {
                        report_decision_mismatch(request, common_args.engine[0], decision_1, common_args.engine[2], decision_3);
                    } else if decision_1 != decision_4 {
                        report_decision_mismatch(request, common_args.engine[0], decision_1, common_args.engine[3], decision_4);
                    }
                }
            }
            _ => unimplemented!()
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
    std::fs::create_dir_all(&common_args.output).expect("failed to create output directory");
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
        let csv_filename = common_args.output.join(format!("{app}.csv"));
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
    eprintln!("generating plot(s)...");
    assert!(
        Command::new("python3")
            .arg("./plot.py")
            .env("BENCHMARK_OUTPUT", &common_args.output)
            .status()
            .unwrap()
            .success(),
        "plot generation failed"
    );
    eprintln!("Done")
}
