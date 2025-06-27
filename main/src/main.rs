#![feature(trait_upcasting)]
use introduction_pods::{
    rsapod::RsaPod
};
use plonky2::{
    field::types::Field,
    hash::{
        poseidon::PoseidonHash,
    },
    plonk::config::Hasher,
};
use pod2::{self,
    middleware::{
        VDSet,
        Params,
        PodId,
        RecursivePod,
        Value,
        containers::{
            Set,
            Array
        },
        RawValue,
    },
    backends::plonky2::{
        Result,
        basetypes::{F},
        mainpod
    },
    frontend::{
        MainPodBuilder,
        MainPod
    },
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
use reqwest;


#[derive(Serialize, Deserialize, Debug)]
struct RSAPodMetaData {
    params: Params,
    vds_root: VDSet,
    id: PodId,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SerializedMainPod {
    params: Params,
    pod_type: (usize, String),
    id: PodId,
    vd_set: VDSet,
    data: serde_json::Value,
}

fn create_rsa_pod() -> Result<()> {
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

    let rsa_pod = RsaPod::new_boxed(&params, &vdset.clone(), msg, &sig, namespace).unwrap();
    print!("RSA Pod created successfully!\n");
    let mut pod_file = File::create("rsa_pod.json").expect("Failed to create file");
    pod_file.write(rsa_pod.serialize_data().to_string().as_bytes()).expect("Failed to write to file");
    let mut metadata_file = File::create("rsa_pod_metadata.json").expect("Failed to create file");
    let meta_data: RSAPodMetaData = RSAPodMetaData {
        params : rsa_pod.params().clone(),
        vds_root : vdset.clone(),
        id : rsa_pod.id().clone(),
    };
    metadata_file.write(serde_json::to_string(&meta_data).unwrap().as_bytes()).expect("Failed to write to file");
    println!("RSA Pod and VDSet written to files successfully!\n");

    Ok(())
}




fn create_rsa_main_pod() -> Result<()> {
    let mut pod_file = File::open("rsa_pod.json").expect("Failed to open file");
    let mut pod_data_str = String::new();
    pod_file.read_to_string(&mut pod_data_str).expect("Failed to read file");
    let rsa_pod_data: serde_json::Value = serde_json::from_str(&pod_data_str).expect("Failed to parse RSA Pod from file");
    let mut metadata_file = File::open("rsa_pod_metadata.json").expect("Failed to open metadata file");

    let mut metadata_str = String::new();
    metadata_file.read_to_string(&mut metadata_str).expect("Failed to read metadata file");
    let metadata: RSAPodMetaData = serde_json::from_str(&metadata_str).expect("Failed to parse metadata from file");
    let rsa_pod = RsaPod::deserialize_data(metadata.params.clone(), rsa_pod_data.clone(), metadata.vds_root, metadata.id)
        .expect("Failed to deserialize RSA Pod from file");

    let params = Params {
        max_input_signed_pods: 0,
        ..Default::default()
    };

    // wrap the rsa_pod in a 'MainPod' (RecursivePod)
    let main_rsa_pod = pod2::frontend::MainPod {
        pod: (rsa_pod.clone() as Box<dyn Any>)
            .downcast::<RsaPod>()
            .unwrap(),
        public_statements: rsa_pod.pub_statements(),
        params: params.clone(),
    };
    let main_rsa_pod_json = serde_json::to_string(&main_rsa_pod)
        .expect("Failed to serialize MainPod to JSON");
    let mut pod_file = File::create("main_rsa_pod.json")
        .expect("Failed to create file");
    pod_file.write(main_rsa_pod_json.as_bytes())
        .expect("Failed to write to file");

    println!("Main RSA Pod created and written to file successfully!");
    Ok(())
}


fn create_group_mainpod(usernames: Vec<String>, pub_keys: Vec<Vec<u8>>, message: String) -> Result<MainPod> {
    let mut pod_file = File::open("main_rsa_pod.json").expect("Failed to open file");
    let mut pod_data_str = String::new();
    pod_file.read_to_string(&mut pod_data_str).expect("Failed to read file");
    let main_rsa_pod_serialized: SerializedMainPod = serde_json::from_str(&pod_data_str).expect("Failed to parse RSA Pod from file");
    let vd_set = main_rsa_pod_serialized.vd_set;
    let params = main_rsa_pod_serialized.params;
    let data: serde_json::Value = main_rsa_pod_serialized.data;
    let pod_id: PodId = main_rsa_pod_serialized.id;
    let pod = <RsaPod as RecursivePod>::deserialize_data(params.clone(), data, vd_set.clone(), pod_id).expect("Failed to deserialize Main Rsa Pod data");
    let public_statements = pod.pub_statements();
    let main_rsa_pod: MainPod = MainPod{
        pod,
        public_statements,
        params : params.clone()
    };
    
    let mut main_pod_builder = MainPodBuilder::new(&params.clone(), &vd_set.clone());

    main_pod_builder.add_recursive_pod(main_rsa_pod.clone());

    let mut list_of_signers : Vec<Value> = Vec::new();
    for pub_key in pub_keys{
        let pk_fields: Vec<F> = pub_key[..].iter().map(|&b| F::from_canonical_u8(b)).collect();
        let pk_hash = PoseidonHash::hash_no_pad(&pk_fields);
        let signer = Value::from(RawValue(pk_hash.elements));
        list_of_signers.push(signer);
    }
    let set_pks = Value::from(Set::new(params.max_depth_mt_containers,
        list_of_signers.into_iter().map(Value::from).collect(),)?);
    let array_usernames = Value::from(Array::new(params.max_depth_mt_containers, usernames.into_iter().map(Value::from).collect(),)?);
    let public_keys_statement = main_pod_builder.pub_op(op!(new_entry, "public_keys", set_pks)).expect("Failed to add public keys set");
    let _user_names_statement = main_pod_builder.pub_op(op!(new_entry, "usernames", array_usernames)).expect("Failed to add usernames array");
    main_pod_builder.pub_op(op!(set_contains, public_keys_statement, (&main_rsa_pod, "rsa_pk"))).expect("Failed to add setContaints");
    main_pod_builder.pub_op(op!(new_entry, "message", Value::from(message))).expect("Failed to add message");
    
    println!("Proving the group pod...");
    let mut prover = mainpod::Prover {};
    let main_pod = main_pod_builder.prove(&mut prover, &params).unwrap();

    let group_pod_json = serde_json::to_string(&main_pod).expect("Failed to serialize MainPod to JSON");
    let mut group_pod_file = File::create("group_pod.json").expect("Failed to create file");
    group_pod_file.write(group_pod_json.as_bytes()).expect("Failed to write to file");

    println!("Group Signature Pod created and written to file successfully!");

    Ok(main_pod)
}


fn _get_group_pod() -> Result<()> {
    //sanity check
    let mut read_file = File::open("group_pod.json").expect("Failed to open file");
    let mut group_pod_str = String::new();
    read_file.read_to_string(& mut group_pod_str).expect("Failed to read file");
    println!("{group_pod_str}");
    //let group_pod: MainPod = serde_json::from_str(&group_pod_str).expect("Failed to parse Main Pod");
    //println!("{:?}", group_pod);
    Ok(())
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    // enter usernames manually
    manual: bool,
    #[arg(short, long)]
    // regenerate group pod
    generate: bool
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
        
        let mut file = File::create("group_list.json").expect("Failed to create file");
        let group_list_json = serde_json::to_string(&group_list).expect("Failed to serialize group list");
        file.write_all(group_list_json.as_bytes()).expect("Failed to write to file");
        println!("Group list written to file successfully!");
    } else{
        let mut file= File::open("group_list.json").expect("Failed to open file");
        let mut group_list_str = String::new();
        file.read_to_string(&mut group_list_str).expect("Failed to read file");
        group_list = serde_json::from_str(&group_list_str).expect(format!("Failed to parse JSON {}", &group_list_str).as_str());
    }

    let (pks, group_list) = get_all_users(group_list.clone()).await.unwrap();
    println!("Group list: {:?}", group_list);
    println!("Message: ");
    let mut message = String::new();
    io::stdin().read_line(&mut message)
        .expect("Failed to read line");
    let message = message.trim().to_string();
    if cli.generate{
        println!("\nCreating new RSA Pod...");
        create_rsa_pod().expect("Failed to create an RSA Pod. Check that your signature is valid and matches the namespace and double-blind message");
        println!("Creating new RSA Main Pod");
        create_rsa_main_pod().expect("Failed to create RSA Main Pod out of RSA Pod");
    }
    println!("\nCreating new Group Signature Pod...");

    let main_pod = create_group_mainpod(group_list.clone(), pks, message)
        .expect(&format!("Failed to create Group Signature Pod. Please check that the signature is created with your GitHub key and that your username is in the list of usernames: {:?}", group_list));

    let main_pod_str = serde_json::to_string(&main_pod).expect("Failed to serialize MainPod to JSON");


    let client = reqwest::Client::new();
    let _res = client.post("http://localhost:8080")
        .body(main_pod_str)
        .send()
        .await.expect("Failed to send request");
}
