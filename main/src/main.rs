#![feature(trait_upcasting)]
use introduction_pods::{
    rsapod::RsaPod
};

use pod2::{self,
    middleware::{
        VDSet,
        Params,
        Pod,
        PodId,
        Hash,
        RecursivePod,
    },
    backends::plonky2::{
        Result
    },
    frontend::MainPodBuilder,
    backends::plonky2::mainpod,
    timed
};
use ssh_key::{
    SshSig
};
use std::fs::File;
use std::io::{self, Read, Write};
use serde_json;
use github_scraper::get_all_users;
use clap::Parser;
use std::any::Any;
use serde::{Deserialize, Serialize};

struct MainPodMetadata {
    params: Params,
    vd_set: VDSet,
    id: PodId,
}

fn get_rsa_pod() -> Result<(Box<dyn Pod>, VDSet)> {
    let params = Params {
        max_input_signed_pods: 0,
        ..Default::default()
    };

    let vds = vec![
        pod2::backends::plonky2::STANDARD_REC_MAIN_POD_CIRCUIT_DATA
            .verifier_only
            .clone(),
        pod2::backends::plonky2::emptypod::STANDARD_EMPTY_POD_DATA
            .1
            .verifier_only
            .clone(),
        introduction_pods::rsapod::STANDARD_RSA_POD_DATA.1.verifier_only.clone(),
    ];
    let vdset = VDSet::new(params.max_depth_mt_vds, &vds).unwrap();

    // Use the sample data from plonky2_rsa
    let msg = "0xPARC";
    let namespace = "double-blind.xyz";
    let sig = SshSig::from_pem(include_bytes!("../signature/github_rsa.sig")).unwrap();
    let vds_root = vdset.root();

    let rsa_pod = timed!(
        "RsaPod::new",
        RsaPod::new(&params, vds_root, msg, &sig, namespace).unwrap()
    );
    Ok((rsa_pod, vdset))
}


fn rsa_pod_with_mainpod_verify() -> Result<()> {
    let mut pod_file= File::open("rsa_pod.json")
        .expect("Failed to open file");
    let mut pod_data_str = String::new();
    pod_file.read_to_string(&mut pod_data_str)
        .expect("Failed to read file");
    let rsa_pod_data: serde_json::Value = serde_json::from_str(&pod_data_str)   
        .expect("Failed to parse RSA Pod from file");
    let mut metadata_file = File::open("metadata.json")
        .expect("Failed to open metadata file");
    let mut metadata_str = String::new();
    metadata_file.read_to_string(&mut metadata_str)
        .expect("Failed to read metadata file");
    let metadata: MetaData = serde_json::from_str(&metadata_str)
        .expect("Failed to parse metadata from file");
    let rsa_pod = RsaPod::deserialize_data(metadata.params.clone(), rsa_pod_data.clone(), metadata.vds_root, metadata.id)
        .expect("Failed to deserialize RSA Pod from file");
    let vds = vec![
        pod2::backends::plonky2::STANDARD_REC_MAIN_POD_CIRCUIT_DATA
            .verifier_only
            .clone(),
        pod2::backends::plonky2::emptypod::STANDARD_EMPTY_POD_DATA
            .1
            .verifier_only
            .clone(),
        introduction_pods::rsapod::STANDARD_RSA_POD_DATA.1.verifier_only.clone(),
    ];
    let params = Params {
        max_input_signed_pods: 0,
        ..Default::default()
    };
    let vdset = VDSet::new(params.max_depth_mt_vds, &vds).unwrap();
    //let (rsa_pod, vd_set) = get_rsa_pod().unwrap();


    rsa_pod.verify().unwrap();

    let params = rsa_pod.params().clone();

    // wrap the rsa_pod in a 'MainPod' (RecursivePod)
    let main_rsa_pod = pod2::frontend::MainPod {
        pod: (rsa_pod.clone() as Box<dyn Any>)
            .downcast::<RsaPod>()
            .unwrap(),
        public_statements: rsa_pod.pub_statements(),
        params: params.clone(),
    };
    
    // let mut pod_file = File::create("main_rsa_pod.json")
    //     .expect("Failed to create file");
    // pod_file.write(main_rsa_pod.serialize_data().to_string().as_bytes())
    //     .expect("Failed to write to file");
    // let mut metadata_file = File::create("metadata.json")
    //     .expect("Failed to create file");
    // let meta_data: MetaData = MetaData {
    //     params : main_rsa_pod.params().clone(),
    //     vds_root : _vdset.root(),
    //     id : main_rsa_pod.id().clone(),
    // };
    // metadata_file.write(serde_json::to_string(&meta_data).unwrap().as_bytes())
    //     .expect("Failed to write to file");


    // now generate a new MainPod from the rsa_pod
    let mut main_pod_builder = MainPodBuilder::new(&params, &vd_set);
    main_pod_builder.add_main_pod(main_rsa_pod);

    let mut prover = pod2::backends::plonky2::mock::mainpod::MockProver {};
    let pod = main_pod_builder.prove(&mut prover, &params).unwrap();
    assert!(pod.pod.verify().is_ok());

    println!("going to prove the main_pod");
    let mut prover = mainpod::Prover {};
    let main_pod = main_pod_builder.prove(&mut prover, &params).unwrap();
    let pod = (main_pod.pod as Box<dyn Any>)
        .downcast::<mainpod::MainPod>()
        .unwrap();
    pod.verify().unwrap();

    Ok(())
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    manual: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct MetaData {
    params: Params,
    vds_root: Hash,
    id: PodId,
}
#[tokio::main]
async fn main() {
    let cli = Args::parse();
    let mut group_list: Vec<String> = Vec::new();
    if cli.manual {
        println!("Manually entering the list of usernames\nEnter the list of usernames. Press enter to add a username. Type 'done' when you are finished.");
        loop {
            let mut username = String::new();
            io::stdin().read_line(&mut username)
                .expect("Failed to read line");
            let username = username.trim();
            if username == "done" {
                break;
            }
            group_list.push(username.to_string());
        }
        println!("Group list: {:?}", group_list);
        let mut file = File::create("group_list.json")
            .expect("Failed to create file");
        let group_list_json = serde_json::to_string(&group_list)
            .expect("Failed to serialize group list");
        file.write_all(group_list_json.as_bytes())
            .expect("Failed to write to file");
        println!("Group list written to file successfully!");
    } else{
        let mut file= File::open("group_list.json")
        .expect("Failed to open file");
        let mut group_list_str = String::new();
        file.read_to_string(&mut group_list_str)
            .expect("Failed to read file");
        group_list = serde_json::from_str(&group_list_str)
            .expect(format!("Failed to parse JSON {}", &group_list_str).as_str());
    }
    
    let _pks = get_all_users(group_list).await;

    
    // ----------- Create RSA Pod and write to file -----------
    // Uncomment the following lines to create an RSA Pod and write it to a file.
    println!("Creating RSA Pod...");
    let (_rsa_pod, _vdset) = get_rsa_pod().map_err(|e| {
        eprintln!("Error creating RSA pod: {}", e);
        std::process::exit(1);
    }).unwrap();
    print!("RSA Pod created successfully!\n");
    let mut pod_file = File::create("rsa_pod.json")
        .expect("Failed to create file");
    pod_file.write(_rsa_pod.serialize_data().to_string().as_bytes())
        .expect("Failed to write to file");
    let mut metadata_file = File::create("metadata.json")
        .expect("Failed to create file");
    let meta_data: MetaData = MetaData {
        params : _rsa_pod.params().clone(),
        vds_root : _vdset.root(),
        id : _rsa_pod.id().clone(),
    };
    metadata_file.write(serde_json::to_string(&meta_data).unwrap().as_bytes())
        .expect("Failed to write to file");
    println!("RSA Pod and VDSet written to files successfully!\n");
    // ----------- Verify RSA Pod with MainPod -----------
    println!("Verifying RSA Pod with MainPod...");
    let res = rsa_pod_with_mainpod_verify();
    match res {
        Ok(_) => println!("RSA Pod with MainPod verification succeeded!"),
        Err(e) => eprintln!("Error during RSA Pod with MainPod verification: {}", e),
    }

}
