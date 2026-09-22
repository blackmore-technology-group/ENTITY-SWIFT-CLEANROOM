import Foundation
import Crypto

let required = ["transaction_record","manifests","asset_provenance","rights","licence","usage_receipt","license_settlement","value_record","digital_commodity","corporate_authorization","capital","share_settlement","event_ledger","external_trust_anchors"]

func jsonData(_ value: Any) throws -> Data {
    try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
}
func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
func sha256(_ text: String) -> String { sha256(Data(text.utf8)) }
func obj(_ value: Any?) -> [String: Any] { value as? [String: Any] ?? [:] }
func arr(_ value: Any?) -> [Any] { value as? [Any] ?? [] }
func s(_ value: Any?, _ key: String) -> String { obj(value)[key] as? String ?? "" }
func i(_ value: Any?, _ key: String) -> Int64 {
    if let n = obj(value)[key] as? NSNumber { return n.int64Value }
    return 0
}
func b(_ value: Any?, _ key: String) -> Bool { obj(value)[key] as? Bool ?? false }
func add(_ errors: inout [String], _ code: String) { if !errors.contains(code) { errors.append(code) } }
func load(_ path: String) throws -> Any { try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath:path))) }
func verifySignature(_ bundle: [String:Any]) -> Bool {
    do {
        let sig=obj(bundle["signature"]); guard s(sig,"alg")=="Ed25519" else { return false }
        guard let der=Data(base64Encoded:s(sig,"public_key_spki_der_b64")), der.count>=32,
              let signature=Data(base64Encoded:s(sig,"sig_b64")) else { return false }
        let raw=der.suffix(32); let key=try Curve25519.Signing.PublicKey(rawRepresentation:raw)
        let header:[String:Any]=["schema":s(bundle,"schema"),"transaction_id":s(bundle,"transaction_id"),"issuer_entity_id":s(bundle,"issuer_entity_id"),"transaction_root_sha256":s(bundle,"transaction_root_sha256")]
        return key.isValidSignature(signature, for: try jsonData(header))
    } catch { return false }
}
func verifyLedger(_ ledger: [String:Any], _ errors: inout [String]) -> Bool {
    let events=arr(ledger["events"]); var prev=String(repeating:"0",count:64)
    for (idx,item) in events.enumerated() {
        let e=obj(item); if i(e,"sequence") != Int64(idx+1) { add(&errors,"LEDGER_SEQUENCE_INVALID"); return false }
        if s(e,"prev_hash") != prev { add(&errors,"LEDGER_PREV_HASH_INVALID"); return false }
        let expected=sha256(prev+":"+String(data:try! jsonData(e["payload"]!),encoding:.utf8)!)
        if s(e,"event_hash") != expected { add(&errors,"LEDGER_EVENT_HASH_INVALID"); return false }; prev=expected
    }
    let cp=obj(ledger["checkpoint"]); if i(cp,"sequence") != Int64(events.count) || s(cp,"head_hash") != prev { add(&errors,"LEDGER_CHECKPOINT_INVALID"); return false }
    return true
}
func verifyBundle(_ bundle:[String:Any]) throws -> [String:Any] {
    var errors:[String]=[]; let ev=obj(bundle["evidence"])
    let root=sha256(try jsonData(ev)); let rootOk=root==s(bundle,"transaction_root_sha256"); if !rootOk { add(&errors,"ROOT_MISMATCH") }
    let sigOk=verifySignature(bundle); if !sigOk { add(&errors,"SIGNATURE_INVALID") }
    var reqOk=true; for section in required where ev[section] == nil { reqOk=false; add(&errors,"MISSING_SECTION:"+section) }
    var cross=true
    if reqOk {
        let tr=obj(ev["transaction_record"]), p=obj(ev["asset_provenance"]), r=obj(ev["rights"]), l=obj(ev["licence"]), u=obj(ev["usage_receipt"])
        let st=obj(ev["license_settlement"]), vr=obj(ev["value_record"]), d=obj(ev["digital_commodity"]), ca=obj(ev["corporate_authorization"]), c=obj(ev["capital"]), ss=obj(ev["share_settlement"])
        if s(p,"asset_id") != s(tr,"asset_id") { cross=false;add(&errors,"PROVENANCE_ASSET_MISMATCH") }
        if s(r,"asset_id") != s(tr,"asset_id") { cross=false;add(&errors,"RIGHTS_ASSET_MISMATCH") }
        if s(r,"claimant_entity_id") != s(l,"grantor_entity_id") { cross=false;add(&errors,"RIGHTS_CLAIMANT_MISMATCH") }
        if s(l,"asset_id") != s(tr,"asset_id") || s(l,"grantor_entity_id") != s(tr,"grantor_entity_id") || s(l,"licensee_entity_id") != s(tr,"licensee_entity_id") || s(l,"rights_claim_id") != s(r,"claim_id") { cross=false;add(&errors,"LICENCE_LINK_MISMATCH") }
        if s(u,"licence_id") != s(l,"licence_id") || s(u,"asset_id") != s(tr,"asset_id") || s(u,"user_entity_id") != s(l,"licensee_entity_id") { cross=false;add(&errors,"USAGE_LINK_MISMATCH") }
        if s(u,"purpose") != s(l,"authorized_purpose") { cross=false;add(&errors,"USAGE_PURPOSE_UNAUTHORIZED") }
        if s(st,"licence_id") != s(l,"licence_id") { cross=false;add(&errors,"SETTLEMENT_LINK_MISMATCH") }
        if s(st,"payer_entity_id") != s(l,"licensee_entity_id") || s(st,"payee_entity_id") != s(l,"grantor_entity_id") { cross=false;add(&errors,"SETTLEMENT_DIRECTION_INVALID") }
        if b(vr,"realized_external") && (s(vr,"settlement_id") != s(st,"settlement_id") || !b(st,"verified_external") || i(vr,"amount_minor") > i(st,"amount_minor")) { cross=false;add(&errors,"VALUE_EXCEEDS_SETTLEMENT") }
        if s(d,"asset_id") != s(tr,"asset_id") || s(d,"usage_id") != s(u,"usage_id") || s(d,"licence_id") != s(l,"licence_id") || s(d,"settlement_id") != s(st,"settlement_id") { cross=false;add(&errors,"COMMODITY_LINK_MISMATCH") }
        if i(d,"contribution_minor") > i(st,"amount_minor") { cross=false;add(&errors,"COMMODITY_EXCEEDS_SETTLEMENT") }
        if s(ca,"share_class_id") != s(c,"share_class_id") || s(ca,"issuance_request_id") != s(c,"issuance_request_id") { cross=false;add(&errors,"CAPITAL_AUTH_MISMATCH") }
        if i(obj(c["accounting"]),"debit_minor") != i(obj(c["accounting"]),"credit_minor") { cross=false;add(&errors,"CAPITAL_ACCOUNTING_UNBALANCED") }
        let positions=arr(c["positions"]); let pos=positions.reduce(Int64(0)){ $0+i($1,"shares") }
        if i(c,"outstanding_before")+i(c,"shares_issued") != i(c,"outstanding_after") || pos != i(c,"outstanding_after") { cross=false;add(&errors,"CAPITAL_SHARES_UNRECONCILED") }
        if s(ss,"capital_event_id") != s(c,"capital_event_id") { cross=false;add(&errors,"SHARE_SETTLEMENT_LINK_MISMATCH") }
    } else { cross=false }
    let ledgerOk=reqOk ? verifyLedger(obj(ev["event_ledger"]),&errors) : false; errors.sort()
    let overall=rootOk && sigOk && reqOk && cross && ledgerOk && errors.isEmpty
    return ["schema":"entity-cleanroom-verification-result-v1","transaction_id":s(bundle,"transaction_id"),"transaction_root_sha256":s(bundle,"transaction_root_sha256"),"root_valid":rootOk,"signature_valid":sigOk,"required_sections_valid":reqOk,"cross_links_valid":cross,"ledger_valid":ledgerOk,"overall_valid":overall,"error_codes":errors]
}
func resultHash(_ result:[String:Any]) throws -> String { sha256(try jsonData(result)) }
func verifyRecovery(_ dir:String,_ keyFile:String) throws -> [String:Any] {
    let m=obj(try load(dir+"/RECOVERY_MANIFEST.json")); let bundle=try Data(contentsOf:URL(fileURLWithPath:dir+"/TRANSACTION_BUNDLE.json")); let enc=try Data(contentsOf:URL(fileURLWithPath:dir+"/STATE_BACKUP.enc")); let keyHex=try String(contentsOfFile:keyFile,encoding:.utf8).trimmingCharacters(in:.whitespacesAndNewlines)
    let key=Data(stride(from:0,to:keyHex.count,by:2).compactMap{idx in let a=keyHex.index(keyHex.startIndex,offsetBy:idx),z=keyHex.index(a,offsetBy:2);return UInt8(keyHex[a..<z],radix:16)})
    var unsigned=m; unsigned.removeValue(forKey:"signature"); let sig=obj(m["signature"]); var sigOk=false
    if let der=Data(base64Encoded:s(sig,"public_key_spki_der_b64")),der.count>=32,let sb=Data(base64Encoded:s(sig,"sig_b64")),let pk=try? Curve25519.Signing.PublicKey(rawRepresentation:der.suffix(32)) { sigOk=pk.isValidSignature(sb,for:try jsonData(unsigned)) }
    let hashes=sha256(bundle)==s(m,"transaction_bundle_sha256") && sha256(enc)==s(m,"encrypted_state_sha256") && sha256(key)==s(m,"recovery_key_fingerprint_sha256")
    var dec=false; var restored=""
    if let nonceData=Data(base64Encoded:s(m,"nonce_b64")), let nonce=try? AES.GCM.Nonce(data:nonceData) {
        let tagBytes=Int(i(m,"tag_bytes"));let ct=enc.prefix(enc.count-tagBytes);let tag=enc.suffix(tagBytes)
        if let box=try? AES.GCM.SealedBox(nonce:nonce,ciphertext:ct,tag:tag),let plain=try? AES.GCM.open(box,using:SymmetricKey(data:key)),let state=try? JSONSerialization.jsonObject(with:plain) { restored=sha256(try jsonData(obj(state)["evidence"]!));dec=true }
    }
    let ok=sigOk && hashes && dec && restored==s(m,"transaction_root_sha256")
    return ["schema":"entity-cleanroom-recovery-result-v1","signature_valid":sigOk,"hashes_valid":hashes,"decrypt_valid":dec,"restored_transaction_root_sha256":restored,"expected_transaction_root_sha256":s(m,"transaction_root_sha256"),"overall_valid":ok]
}
let args=CommandLine.arguments
if args.count>1 && args[1] != "test" {
    let result=try verifyBundle(obj(try load(args[1])));let out:[String:Any]=["result_sha256":try resultHash(result),"result":result]
    print(String(data:try jsonData(out),encoding:.utf8)!);exit((result["overall_valid"] as? Bool)==true ? 0:1)
}
let kit=URL(fileURLWithPath:FileManager.default.currentDirectoryPath).appendingPathComponent("conformance-kit").path
let manifest=obj(try load(kit+"/vectors/VECTOR_MANIFEST.json"));let vectors=arr(manifest["vectors"]);var rows:[[String:Any]]=[];var passed=0
for item in vectors {
    let v=obj(item);let result=try verifyBundle(obj(try load(kit+"/vectors/"+s(v,"file"))));let exp=obj(v["expected"])
    let actualErrors = try jsonData(result["error_codes"]!)
    let expectedErrors = try jsonData(exp["error_codes"]!)
    let ok=(result["overall_valid"] as? Bool)==(exp["overall_valid"] as? Bool) && actualErrors == expectedErrors
    if ok { passed += 1 };rows.append(["name":s(v,"name"),"ok":ok,"result_sha256":try resultHash(result),"result":result])
}
let recovery=try verifyRecovery(kit+"/vectors/recovery",kit+"/vectors/test_inputs/recovery_key.hex")
let report:[String:Any]=["implementation":"swift","vectors_passed":passed,"vectors_total":vectors.count,"recovery_pass":recovery["overall_valid"] as? Bool ?? false,"golden_root":manifest["valid_transaction_root_sha256"]!,"results":rows,"recovery":recovery]
let out=try JSONSerialization.data(withJSONObject:report,options:[.prettyPrinted,.sortedKeys,.withoutEscapingSlashes]);print(String(data:out,encoding:.utf8)!)
if passed != vectors.count || (recovery["overall_valid"] as? Bool) != true { exit(1) }
