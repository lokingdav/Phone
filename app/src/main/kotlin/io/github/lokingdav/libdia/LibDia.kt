package io.github.lokingdav.libdia

object LibDia {
    init { System.loadLibrary("dia_jni") } // name of your .so

    // ===================== DH =====================
    external fun dhKeygen(): Array<ByteArray> // [sk(Fr 32B), pk(G1 32B)]
    external fun dhComputeSecret(sk: ByteArray, peerPk: ByteArray): ByteArray // secret (G1 32B)

    // =================== VOPRF ====================
    external fun voprfKeygen(): Array<ByteArray>                 // [sk(Fr), pk(G2)]
    external fun voprfBlind(input: ByteArray): Array<ByteArray>  // [blinded(G1), blind(Fr)]
    external fun voprfEvaluate(blinded: ByteArray, sk: ByteArray): ByteArray // element(G1)
    external fun voprfUnblind(element: ByteArray, blind: ByteArray): ByteArray // Y(G1)
    external fun voprfVerify(input: ByteArray, Y: ByteArray, pk: ByteArray): Boolean
    external fun voprfVerifyBatch(inputs: Array<ByteArray>, Ys: Array<ByteArray>, pk: ByteArray): Boolean

    // ===================== AMF ====================
    external fun amfKeygen(): Array<ByteArray> // [sk(Fr), pk(G1)]
    external fun amfFrank(
        skSender: ByteArray,
        pkReceiver: ByteArray,
        pkJudge: ByteArray,
        msg: ByteArray
    ): ByteArray // opaque sig blob
    external fun amfVerify(
        pkSender: ByteArray,
        skReceiver: ByteArray,
        pkJudge: ByteArray,
        msg: ByteArray,
        sig: ByteArray
    ): Boolean
    external fun amfJudge(
        pkSender: ByteArray,
        pkReceiver: ByteArray,
        skJudge: ByteArray,
        msg: ByteArray,
        sig: ByteArray
    ): Boolean

    // ===================== BBS ====================
    external fun bbsKeygen(): Array<ByteArray> // [sk(Fr), pk(G2)]

    // NEW: returns opaque signature blob (single byte[])
    external fun bbsSign(msgs: Array<ByteArray>, sk: ByteArray): ByteArray

    // NEW: verify using opaque signature blob
    external fun bbsVerify(msgs: Array<ByteArray>, pk: ByteArray, sigBlob: ByteArray): Boolean

    // NEW: proof creation takes sig blob (not A/e)
    external fun bbsCreateProof(
        msgs: Array<ByteArray>,
        discloseIdx1b: IntArray?, // 1-based indices; null or empty => no disclosure
        pk: ByteArray,
        sigBlob: ByteArray,
        nonce: ByteArray? // optional; null => empty nonce
    ): ByteArray // opaque proof blob

    external fun bbsVerifyProof(
        disclosedIdx1b: IntArray?,           // must align with disclosedMsgs size
        disclosedMsgs: Array<ByteArray>?,    // may be null/empty if no disclosures
        pk: ByteArray,
        nonce: ByteArray?,                   // same nonce used in create
        proof: ByteArray                     // opaque proof blob
    ): Boolean
}
