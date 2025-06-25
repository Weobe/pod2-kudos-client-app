use introduction_pods::{
    rsapod::RsaPod
};

use pod2::{self,
    middleware::{
        VDSet,
        Params,
        Pod
    },
    backends::plonky2::{
        Result,
    },
    timed
};
use ssh_key::{
    SshSig
};
use std::fs::File;
use std::io::Write;
use tokio::net::TcpListener;
use github_scraper::get_all_users;

fn get_rsa_pod(path: String) -> Result<(Box<dyn Pod>, VDSet)> {
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
    let msg = "0xPARC\n";
    let namespace = "double-blind.xyz";
    let sig = SshSig::from_pem(include_bytes!("../signature/id_rsa.sig")).unwrap();
    let vds_root = vdset.root();

    let rsa_pod = timed!(
        "RsaPod::new",
        RsaPod::new(&params, vds_root, msg, &sig, namespace).unwrap()
    );
    Ok((rsa_pod, vdset))
}

#[tokio::main]
async fn main() {
     let user_list: Vec<String> = vec![
            "Weobe".to_string(),
            "psquare1".to_string(),
            "lizahorokh".to_string(),
    ];
    let pks = get_all_users(user_list).await;
    println!("Public keys: {:?}", pks);
    // let (_rsa_pod, _vdset) = get_rsa_pod().map_err(|e| {
    //     eprintln!("Error creating RSA pod: {}", e);
    //     std::process::exit(1);
    // }).unwrap();
    // print!("RSA Pod created successfully!\n");
    // let mut pod_file = File::create("rsa_pod.json")
    //     .expect("Failed to create file");
    // pod_file.write(format!("{_rsa_pod:?}\n").as_bytes())
    //     .expect("Failed to write to file");
    // let mut vd_file = File::create("rsa_vd.json")
    //     .expect("Failed to create file");
    // vd_file.write(format!("{_vdset:?}\n").as_bytes())
    //     .expect("Failed to write to file");
    // println!("RSA Pod and VDSet written to files successfully!\n");
}
