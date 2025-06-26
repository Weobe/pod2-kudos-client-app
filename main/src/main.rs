#![feature(trait_upcasting)]
use introduction_pods::{
    rsapod::RsaPod
};
use plonky2::{
    field::types::Field,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    plonk::config::Hasher,
};
use pod2::{self,
    middleware::{
        VDSet,
        Params,
        Pod,
        PodId,
        Hash,
        RecursivePod,
        Value,
        containers::Set,
        RawValue,
        KEY_SIGNER,
        CustomPredicateRef, PodType, Predicate, Statement,
        StatementArg, TypedValue, KEY_TYPE, Operation
    },
    backends::plonky2::{
        Result,
        basetypes::{C, D, F},
    },
    frontend::{
        MainPodBuilder,
        MainPod
    },
    backends::plonky2::mainpod,
    timed,
    op
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

#[derive(Serialize, Deserialize, Debug)]
struct MainPodMetaData {
    params: Params,
    vd_set: VDSet,
    id: PodId,
}

#[derive(Serialize, Deserialize, Debug)]
struct RSAPodMetaData {
    params: Params,
    vds_root: VDSet,
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
        RsaPod::new_boxed(&params, &vdset.clone(), msg, &sig, namespace).unwrap()
    );
    print!("RSA Pod created successfully!\n");
    let mut pod_file = File::create("rsa_pod.json")
        .expect("Failed to create file");
    pod_file.write(rsa_pod.serialize_data().to_string().as_bytes())
        .expect("Failed to write to file");
    let mut metadata_file = File::create("metadata.json")
        .expect("Failed to create file");
    let meta_data: RSAPodMetaData = RSAPodMetaData {
        params : rsa_pod.params().clone(),
        vds_root : vdset.clone(),
        id : rsa_pod.id().clone(),
    };
    metadata_file.write(serde_json::to_string(&meta_data).unwrap().as_bytes())
        .expect("Failed to write to file");
    println!("RSA Pod and VDSet written to files successfully!\n");

    Ok((rsa_pod, vdset))
}




fn get_main_pod_from_rsa_pod() -> Result<(MainPod, VDSet)> {
    let mut pod_file = File::open("rsa_pod.json")
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
    let metadata: RSAPodMetaData = serde_json::from_str(&metadata_str)
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
    rsa_pod.verify().unwrap();

    // wrap the rsa_pod in a 'MainPod' (RecursivePod)
    let main_rsa_pod = pod2::frontend::MainPod {
        pod: (rsa_pod.clone() as Box<dyn Any>)
            .downcast::<RsaPod>()
            .unwrap(),
        public_statements: rsa_pod.pub_statements(),
        params: params.clone(),
    };
    //println!("{:?}", main_rsa_pod);
    let main_rsa_pod_json = serde_json::to_string(&main_rsa_pod)
        .expect("Failed to serialize MainPod to JSON");
    
    let mut pod_file = File::create("main_rsa_pod.json")
        .expect("Failed to create file");
    pod_file.write(main_rsa_pod_json.as_bytes())
        .expect("Failed to write to file");
    println!("Main RSA Pod created and written to file successfully!");
    Ok((main_rsa_pod, vdset))
}


fn get_actual_group_mainpod(pub_keys: Vec<Vec<u8>>) -> Result<()> {
    let (main_rsa_pod, vd_set) = get_main_pod_from_rsa_pod().unwrap();
    let params = main_rsa_pod.params.clone();
    let mut main_pod_builder = MainPodBuilder::new(&params, &vd_set);
    main_pod_builder.add_recursive_pod(main_rsa_pod.clone());

    let mut list_of_signers : Vec<Value> = Vec::new();
    for pub_key in pub_keys{
        let pk_fields: Vec<F> = pub_key[..].iter().map(|&b| F::from_canonical_u8(b)).collect();
        let pk_hash = PoseidonHash::hash_no_pad(&pk_fields);
        let signer = Value::from(RawValue(pk_hash.elements));
        list_of_signers.push(signer);
    }
    let set_username = Value::from(Set::new(params.max_depth_mt_containers,
        list_of_signers.into_iter().map(Value::from).collect(),)?);
    main_pod_builder.pub_op(op!(set_contains, set_username, (&main_rsa_pod, "rsa_pk")));

    let mut prover = pod2::backends::plonky2::mock::mainpod::MockProver {};
    let pod = main_pod_builder.prove(&mut prover, &params).unwrap();
    assert!(pod.pod.verify().is_ok());

    println!("going to prove the main group pod");
    let mut prover = mainpod::Prover {};
    let main_pod = main_pod_builder.prove(&mut prover, &params).unwrap();
    // let pod = (main_pod.pod as Box<dyn Any>)
    //     .downcast::<mainpod::MainPod>()
    //     .unwrap();
    // pod.verify().unwrap();

    let group_pod_json = serde_json::to_string(&main_pod).expect("Failed to serialize MainPod to JSON");
    let mut group_pod_file = File::create("group_pod.json").expect("Failed to create file");
    group_pod_file.write(group_pod_json.as_bytes()).expect("Failed to write to file");

    //sanity check
    let mut read_file = File::open("group_pod.json").expect("Failed to open file");
    let mut group_pod_str = String::new();
    read_file.read_to_string(& mut group_pod_str).expect("Failed to read file");
    let group_pod_value: MainPod = serde_json::from_str(&group_pod_str).expect("Failed to parse Main Pod");
    println!("{:?}", group_pod_value);
    // let main_pod_json = serde_json::to_string(&pod.serialize_data())
    //     .expect("Failed to serialize MainPod to JSON");
    
    // let mut pod_file = File::create("new_main_pod.json")
    //     .expect("Failed to create file");
    // pod_file.write(main_pod_json.as_bytes())
    //     .expect("Failed to write to file");

    // let metadata: MainPodMetaData = MainPodMetaData {
    //     params: pod.params().clone(),
    //     vd_set: vd_set.clone(),
    //     id: pod.id().clone(),
    // };
    // let metadata_json = serde_json::to_string(&metadata)
    //     .expect("Failed to serialize MainPod metadata to JSON");
    // let mut metadata_file = File::create("main_pod_metadata.json")
    //     .expect("Failed to create metadata file");
    // metadata_file.write(metadata_json.as_bytes())
    //     .expect("Failed to write metadata to file");
    println!("Main Pod created and written to file successfully!");

    Ok(())
}

fn get_group_pod() -> Result<Box<dyn Pod>> {
    let mut main_pod_from_file = File::open("new_main_pod.json")
        .expect("Failed to open Main Pod file");
    let mut main_pod_data_str = String::new();
    main_pod_from_file.read_to_string(&mut main_pod_data_str)
        .expect("Failed to read Main Pod file");
    let main_pod_data: serde_json::Value = serde_json::from_str(&main_pod_data_str)
        .expect("Failed to parse Main Pod from file");  
    let mut new_metadata_file = File::open("main_pod_metadata.json")
        .expect("Failed to open Main Pod metadata file");
    let mut new_metadata_str = String::new();
    new_metadata_file.read_to_string(&mut new_metadata_str)
        .expect("Failed to read Main Pod metadata file");
    let new_metadata: MainPodMetaData = serde_json::from_str(&new_metadata_str)
        .expect("Failed to parse Main Pod metadata from file");
    let new_main_pod = mainpod::MainPod::deserialize_data(new_metadata.params.clone(), main_pod_data, new_metadata.vd_set.clone(), new_metadata.id).unwrap();
    new_main_pod.verify().unwrap();
    //println!("{:?}", new_main_pod.pub_statements());
    //println!("{:?}", new_main_pod.pub_self_statements());
    Ok(new_main_pod)
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    manual: bool,
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
    
    let pks = get_all_users(group_list).await.unwrap();
    let _ = get_actual_group_mainpod(pks).unwrap();
    //let new_pod = get_group_pod().unwrap();
}
