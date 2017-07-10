#!/bin/bash

# Download pcaps from www.pcapr.net. The pcap ids can be found by selecting
# 'protocols' from the top bar of www.pcapr.net, selecting the relevant
# protocol name, and then inspecting the page source with the Chrome browser.

if [ -z $1 ]; then
    echo "USAGE: $0 <test_pcap_dir>"
    exit
fi

username=luke.valenta@gmail.com
password=XcxjLwagnKRYF2ACZ2Q6
pcapdir=$1

ssh_ids="
    3ca92db8389f36a2b1983b4fb939be5d
    d1e33523a8ccaf659e4c03b9f3c693a3
    d091e2965994724eb310b3e998bbf00d
    a2447b5f87ff803b92cd4a26e9dd34a1
    de357768a89f57c30428f7c3ee4b488e
    27a0080bc259e9b7ed88f80b4368b6df
    b7242fd1a6fc266c09c3a222bad195c5
    a094700d574dcffa258c2ba19731440a
    92671c9edb695af4e57d036343cdbedc
    ddc3b761ea918108ed8d64abeaa19d4a
    b0a3b649e6b3b37ecc9115b58b96beb6
    485772f7a42894de6e779ca5dd958562
    fccafcd194d6c47a1019fefe8e90950a
    373003f2e34ae2769c07d4bf065fa4af
    3eee990a91aec5142c3d1953fda3bbfc
    3ca92db8389f36a2b1983b4fb939be5d
    80998f4345dea2ef46d847841f3b7327
    d1e33523a8ccaf659e4c03b9f3c693a3
    c20514974d5d2fcac58087f046dd983d
    bfa989111f56be8d6f0a9c6902047fb4
    ddb40a805e09df68a7755e99bd4473fe
    54d88a5fc74ff079e1690a75bb75dd40
    17ae17862cb291f1faf6eaca8f0153ec
    0a4733614fc692796a4e4409cf51a7a9
    066f6af9d7cba47f84ad233abaa417bd
    173ac370984050348ee43a6a2c5689d5
    34ca76fcb8d7a70ed89010d510100147
    221beb1c7cbf71d237aabd0fde2df3da
    5670b222406f2831dac227a46fd0e1f1
    7198a8cc224bd76485900c184fdc0184
    2595ebd9715a81452272cf468e1923fd
    a896eb7c15c0b6e477fa489862a033b1
    e8ecb2c9369ba95ba549c6dfdf7b0993
    4f79a4ff4acafe37ebfecac8ee869080
"

# Choose protocol 'ssl'
tls_ids="
    25f6fdee7a2b7f41366c48bc210bd634
    cd32a2522695442278eb2b294b24ccff
    bdd774b15f29408a965867b74a5a1f41
    205f07b5a22f93ae144a19faea5e5d55
    f6afcaa33ec37e15aed10efc62cca79c
    8f36c6ef69490e804d623f4db99b2bb7
    530c0dea9e2cdf0c091b5c77e4e70afc
    4450959233ec05524f8b0d3893929633
    38e49a476ce14faf3876ecd84915c803
    86b9a19561144ade4a8dfef21c0c5737
    f16b13fe9af94154d682aad0ae1163be
    f4288b3792622eb1338e9a2be5ae8013
    bb4dfea5362ed5fa898516e325bf51d2
    58768beb0032ffa76f1ba7134ac0a7d5
    f54be5787808b0ef10472bf037852f22
    8e520af6c793463d4449f5c5dc2f4b4e
    262dd727a1a406db7ee7ccac389201d1
    0d9dad35013bb3dd0866f1f715c4d813
    2cc5886af7dda1c28c4e50b4f2bb9a77
    4ff360305f07ac7fce7522cd64548cf5
    0f0aae61c44e78f41dbb85a5b68ba9b2
    025dcad88b83ccd6b1dd74b8d377895e
    a0683d8119eb000ef15fa89ca715b2e9
    166c01d21315f82c5e582ac6aa070947
    c24e0624938d3b1acb004a071b4e168f
    76fd0570a5278e11724a25eacdc39136
    342496eab4a89a914a07312a2b57d75d
    4450959233ec05524f8b0d3893929633
    38e49a476ce14faf3876ecd84915c803
    bb4dfea5362ed5fa898516e325bf51d2
    58768beb0032ffa76f1ba7134ac0a7d5
    262dd727a1a406db7ee7ccac389201d1
    fcf108bd8cb63fa1fa14ffba00586198
"

mkdir -p $pcapdir/ssh
for id in $ssh_ids
do
    filename=$pcapdir/ssh/$id.pcap
    if [ ! -f $filename ]; then
        curl --basic -u $username:$password http://www.pcapr.net/api/download?id=$id > $filename
    fi
done

mkdir -p $pcapdir/tls
for id in $tls_ids
do
    filename=$pcapdir/tls/$id.pcap
    if [ ! -f $filename ]; then
        curl --basic -u $username:$password http://www.pcapr.net/api/download?id=$id > $filename
    fi
done
