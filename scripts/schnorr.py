from poseidon import Poseidon

# Chosen parameters for the Schnorr protocol; use `schorr_gen.py` for new params

SCH_G_16 = 46292
SCH_P_16 = 52813
SCH_Q_8 = 163

# Full round = 2, partial round = 1 verification


def schnorr_impl(x_sch, g_sch, p_sch, q_sch, hash_fn):

    y_sch = pow(g_sch, x_sch, p_sch)

    #### Signing
    msg = 0xAA
    k_sch = int(hash_fn.run_hash([msg, x_sch, 0, 0])) % (q_sch - 1) + 1

    r_sch = pow(g_sch, k_sch, p_sch)
    h_sch = int(hash_fn.run_hash([msg, r_sch, 0, 0])) % q_sch

    hx_sch = (h_sch * x_sch) % q_sch
    s_sch = (k_sch - hx_sch) % q_sch
    # Signature is (s_sch, h_sch)

    #### Verification
    r_left = pow(g_sch, s_sch, p_sch)
    r_right = pow(y_sch, h_sch, p_sch)
    r_v = (r_left * r_right) % p_sch
    h_v = int(hash_fn.run_hash([msg, r_v, 0, 0])) % q_sch

    print(f'Signature: {x_sch=}, {g_sch=}, {p_sch=}, {q_sch=}, {y_sch=}')
    print(f'Signature: {k_sch=}, {r_sch=}, {h_sch=}, {hx_sch=}, {s_sch=}')
    print(f'Verification:  {h_v=}, {r_left=}, {r_right=}, {r_v=}')
    print("Signature valid" if h_v == h_sch else "***** Signature invalid *****")
    print()


def schnorr_p8():
    print("Schnorr 8-bit")
    #### Initialization
    x_sch = 1
    g_sch = SCH_G_8 = 61
    p_sch = SCH_P_8 = 199
    q_sch = SCH_Q_4 = 11

    H8_r1 = Poseidon(p=p_sch,
                     security_level=8,
                     alpha=5,
                     input_rate=None,
                     t=4,
                     full_round=2,
                     partial_round=1)
    print(f'DEBUG H8_r1.rc_field=\n{[int(rc) for rc in H8_r1.rc_field]}')
    print(f'DEBUG H8_r1.mds_matrix=\n{H8_r1.mds_matrix}')
    schnorr_impl(x_sch, g_sch, p_sch, q_sch, H8_r1)


def schnorr_p32():
    print("Schnorr 32-bit")
    #### Initialization
    x_sch = 41231  # Random [1, q-1]
    g_sch = SCH_G_32 = 3196401078
    p_sch = SCH_P_32 = 3552575077
    q_sch = SCH_Q_16 = 43607

    H32_r1 = Poseidon(p=p_sch,
                      security_level=32,
                      alpha=5,
                      input_rate=None,
                      t=4,
                      full_round=8,
                      partial_round=56)
    schnorr_impl(x_sch, g_sch, p_sch, q_sch, H32_r1)


def schnorr_p256():
    print("Schnorr 256-bit")
    #### Initialization
    x_sch = 7  # Random [1, q-1]
    g_sch = SCH_G_256 = 538656022598842469454643169739039226046068127485250539718667697143229884313993908482467458720523657119851551238136866900410675393842937078133579349397450
    p_sch = SCH_P_256 = 7045057217230447731457141224677172304938024641107125703085664679679562591330516280806915841051104795334033208720557188019515514918287181789975220693499439
    q_sch = SCH_Q_128 = 65733587161108449460168259508558239845424631360925658890317611045035932762599

    H256_r1 = Poseidon(p=p_sch,
                      security_level=256,
                      alpha=5,
                      input_rate=None,
                      t=4,
                      full_round=2,
                      partial_round=1)
    schnorr_impl(x_sch, g_sch, p_sch, q_sch, H256_r1)



def schnorr_p64():
    print("Schnorr 64-bit")
    #### Initialization
    x_sch = 7  # Random [1, q-1]
    g_sch = SCH_G_64 = 16338291796031708793
    p_sch = SCH_P_64 = 18005185968437325397
    q_sch = SCH_Q_32 = 2791706791

    H64_r1 = Poseidon(p=p_sch,
                      security_level=64,
                      alpha=5,
                      input_rate=None,
                      t=4,
                      full_round=8,
                      partial_round=56)
    schnorr_impl(x_sch, g_sch, p_sch, q_sch, H64_r1)


def schnorr_p128():
    print("Schnorr 128-bit")
    #### Initialization
    x_sch = 7  # Random [1, q-1]
    g_sch = SCH_G_128 = 242321785765686127959664509210735233889
    p_sch = SCH_P_128 = 295090870502302888741081815488172298301
    q_sch = SCH_Q_32 = 14800766124420507947

    H128_r1 = Poseidon(p=p_sch,
                      security_level=128,
                      alpha=3,
                      input_rate=None,
                      t=4,
                      full_round=8,
                      partial_round=56)
    schnorr_impl(x_sch, g_sch, p_sch, q_sch, H128_r1)




def schnorr_p2048():
    print("Schnorr 2048-bit")
    #### Initialization
    x_sch = 0x30ca7ab1624510c05b92171bb34bc43158eff0d2346f14222d744f6872aa14a2bfb9b23bf1da5a91dc8c85b172162c75ae1bda8fe7a4c67510ec4a4fc9616b137daee9768ec25fca762f5a464f759e564cd6a19076df56c4f1f69e5d78b1e1eedf217139bfa27451f630181f793efa8bb9341ff212edbd7fe1e6e6b3f5346c48
    p_sch = 0xa36e3e1a05f9410258467ef86d4fd84d3b658195b146db8508696529e408970ec1e675c2744266a2ef8f472ae571cd424a9b2b35c416cd9b330c5f8fca473ae5d33b7f644eef91ebce66b589997b4e46c5fda3f6ab1de060d62c8bbb08cd278afe4df5206da40e33abbc4370a4696ffb758580ea44fe973c453e692c20141790ddf492bb71f5f7ce3df89f1f2fdcb57fcb600ba8b72ffc5b630f6f0ac8ac52e0d5b7042dc4c1e9066ea81342028acb2af24b54c084a94c48977e762bed1e9da27f5f2f200ae26b2e4a00cdb26471af962b7a7f70a8621a789d2b4d7bc8fad6f8b87e2bc6661035731e8b39b3ffd378caa27920350d05b8ed80fb4e59910e33ff
    g_sch = 0x2d135d52611b55e84b9299ae0507880aa4b9cf762cb0ed54274c288984880567dfae95edb5c08dc44af26dad5a5eb964b4b06bae856df04b5dc8c26618a1ad5853be08d14d4368c19189dc35ecbd642287f4a94021f7991ce173329a9e2acb825441bd756ed032dc6b3ca1089d1fb073d57af01c84dcd1db28c97ea399fe9f96e13a7eb0f5dc4edac37a006d29ffbb14c4797d9f4f94502f0c0510d80e452c5de7ac0ced9f323f9a2bf99835c616931dee183e3b7d995f47ce8dcbb40922ea8cd87e72bc0460c29e945a5770e3cea10464fd340c10893ce89ca0ccd9183ef7bd70f9826ab2e489601358a32b83f6381edb246194444e0aafa0960d6c12b4742a
    q_sch = 0x844a49d3a4096b42d1cf9008691cb0612d2d8fe7e464f4ef896e12a9ecd2e7f7088c98ecee06897e24909ef8e30298c0ce18d10724deb4881d5c203bcc972f43763e98f2745ba086da6da868a4e195d159a6a080ff715336fdcf8f889049cee7249c34f2a1902332ef65ea5a657de2892a85866d07eebadcc468c58e8284e429

    H2048_r1 = Poseidon(p=p_sch,
                        security_level=2048,
                        alpha=3,
                        input_rate=None,
                        t=4,
                        full_round=8,
                        partial_round=56)
    schnorr_impl(x_sch, g_sch, p_sch, q_sch, H2048_r1)


if __name__ == "__main__":
    schnorr_p8()
    # schnorr_p32()
    # schnorr_p64()
    # schnorr_p128()
    # schnorr_p256()
    # schnorr_p2048()
