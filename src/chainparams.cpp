// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.

        pchMessageStart[0] = 0x3e;    
        pchMessageStart[1] = 0xb3;
        pchMessageStart[2] = 0xfe;
        pchMessageStart[3] = 0xa0;
        vAlertPubKey = ParseHex("041d0712f1236e07a9ce6066a6cc603791490324d7d8530fae9bf1d6a935f5c32a8c3010ac6033abb349f7e0859c89ba51fa4aeb79abd7cb7f9231e2d64f3f9a72");
        nDefaultPort = 25752;
        nRPCPort = 25753;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 10);


        const char* pszTimestamp = "Presenting >>>>>>>>>>>>>>>> PSZTimeStamp <<<<<<<<<<<<<<<<<<<";
        CTransaction txNew;
        txNew.nTime = 1434020000;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 1434020000 << CBigNum(72225) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1434020000;
        genesis.nBits    = 0x2100ffff;
        genesis.nNonce   = 135;


        hashGenesisBlock = uint256("0x001611f5d3623e8ff135714833fa0d135c45f9981d8854ec0f9f44e29426e8d1");

        hashGenesisBlock = genesis.GetHash(); 

        assert(hashGenesisBlock == uint256("0x001611f5d3623e8ff135714833fa0d135c45f9981d8854ec0f9f44e29426e8d1"));
        assert(genesis.hashMerkleRoot == uint256("0x6e371e5fb6ee10651057b7b1cb88463aa261f56454145565a3b677ee0c9a791f"));

        base58Prefixes[PUBKEY_ADDRESS] 		= list_of(28);
        base58Prefixes[SCRIPT_ADDRESS] 		= list_of(72);
        base58Prefixes[SECRET_KEY] 			= list_of(572);
        base58Prefixes[EXT_PUBLIC_KEY] 		= list_of(0x1e)(0x4b)(0xb1)(0x87);
        base58Prefixes[EXT_SECRET_KEY] 		= list_of(0x7c)(0xca)(0x6a)(0xc3);

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        nTargetSpacing = 40; // seconds
        
        nLastPOWBlock  = 1000000;

        nFirstPoSBlock = 1000;
        nCoinbaseMaturity = 25;
        nLaunchTime = txNew.nTime;
        nStakeMinAge = 12 * 60 * 60;
        nModifierInterval = 1 * 60;

        nMasternodeFixReward = 1000 * COIN;
        nMasternodeProportionalReward = 60; // Percent
        nMasternodeValue = 17259.22 * COIN;
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet (COMMENTED, PLEASE UNCOMMENT IN ORDER TO USE)
//
/*

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.

        pchMessageStart[0] = 0x53;
        pchMessageStart[1] = 0x07;
        pchMessageStart[2] = 0x19;
        pchMessageStart[3] = 0x6d;

        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);

        vAlertPubKey = ParseHex("04d65960d060168c6ad6efd2f8cf7bd146ca0f3c9fe070e70f7104729b7abd2fcc25a76b4ceac500e5bd5a105f541be0347cd3294139018294f339431bd5f10d72");

        nDefaultPort = 25007;
        nRPCPort = 25008;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 124128; //97968;

        hashGenesisBlock = uint256("0x00006dbe104010a3f14bf569d57c795fd4ad4609566ee005d56bae8f91495225");

        if (false && (genesis.GetHash() != hashGenesisBlock))
        {
            uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
            while (genesis.GetHash() > hashTarget)
            {
                ++genesis.nNonce;
                if (genesis.nNonce == 0)
                {
                    printf("NONCE WRAPPED, incrementing time");
                    ++genesis.nTime;
                }
            }
            cout << "genesis: \n" << genesis.ToString() << endl;
            cout << "genesis.GetHash(): " << genesis.GetHash().ToString() << endl;
            cout << "genesis.hashMerkleRoot: " << genesis.hashMerkleRoot.ToString() << endl;
            cout << "genesis.nTime: " << genesis.nTime << endl;
            cout << "genesis.nNonce: " << genesis.nNonce << endl;
        }

        hashGenesisBlock = genesis.GetHash(); 
        assert(hashGenesisBlock == uint256("0x00006dbe104010a3f14bf569d57c795fd4ad4609566ee005d56bae8f91495225"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = list_of(117);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(164);
        base58Prefixes[SECRET_KEY]     = list_of(219);

        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        nTargetSpacing = 10; // seconds

        nLastPOWBlock = 0x7fffffff;
        nInstaMinePoWReward = 0 * COIN;
        nInstaMineLastBlock = 1440;
        nRegularPoWReward = 10000 * COIN;

        nFirstPoSBlock = 7000;
        nCoinbaseMaturity = 200;
        nLaunchTime = 1433538000;
        nStakeMinAge = 1 * 60 * 60;
        nModifierInterval = 1 * 60;
        nPoSCoinReward = 15; // percents
        nAdvisablePoSTxOut = 10000 * COIN;

        nMasternodeFixReward = 50 * COIN;
        nMasternodeProportionalReward = 20; // percents
        nMasternodeValue = 50000 * COIN;
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;

*/

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
//        case CChainParams::TESTNET:
//            pCurrentParams = &testNetParams;
//            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    
//    bool fTestNet = GetBoolArg("-testnet", false);
    
//    if (fTestNet) {
//        SelectParams(CChainParams::TESTNET);
//    } else {
        SelectParams(CChainParams::MAIN);
//    }
    return true;
}
