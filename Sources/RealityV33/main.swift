import Foundation
import Crypto

let kitPath = "reality-conformance-kit/ENTITY_V3_3_REALITY_CLEANROOM_KIT.min.json"
let kitSHA = "f8b39ee01fb7346f33a57530e925b545d2bf9a770c7ec60724e28a4971d55a46"
let expected = "82bd1f1fb328edd37a26d8ea60ede5a599c7d9af5027bffd73b9e52843b5a51d"
let primitives = ["ENTITY","AUTHORITY","RIGHT","EVENT","VALUE"]
let states:Set<String> = ["OBSERVED","ASSERTED","INFERRED","ATTESTED","EXTERNALLY_VERIFIED","ADJUDICATED","DISPUTED","REVOKED","UNKNOWN"]
let evidence:Set<String> = ["SENSOR_OBSERVATION","DOCUMENT","REGISTRY_RECORD","LAB_RESULT","PAYMENT_RECORD","IMAGE","API_RESPONSE","CERTIFICATE","COURT_RECORD","OTHER"]
let anchors:Set<String> = ["GOVERNMENT_REGISTRY","SENSOR_NETWORK","BANK_SETTLEMENT","LAB_SYSTEM","SUPPLY_CHAIN_SYSTEM","CORPORATE_REGISTRY","COURT_RECORD","CERTIFICATE_AUTHORITY","OTHER"]
let nodes:Set<String> = ["SOURCE_DATA","DCO","RIGHT","LICENSE","USAGE","DERIVED_ASSET","PRODUCT","TRANSACTION","REVENUE","SETTLEMENT","CONTRIBUTOR"]
let edges:Set<String> = ["ORIGINATED_FROM","AUTHORIZED_BY","LICENSED_AS","USED_IN","DERIVED_FROM","PRODUCED","GENERATED","SETTLED_AS","CONTRIBUTED_TO"]
func sha(_ data:Data)->String { SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined() }
func obj(_ v:Any?)->[String:Any] { v as? [String:Any] ?? [:] }
func s(_ r:[String:Any],_ k:String)->String { r[k] as? String ?? "" }
func b(_ r:[String:Any],_ k:String,_ w:Bool)->Bool { (r[k] as? Bool) == w }
func hex64(_ v:Any?)->Bool { guard let x=v as? String,x.count==64 else{return false};return x.allSatisfy{$0.isNumber || ("a"..."f").contains(String($0))} }
func refs(_ v:Any?,_ nonempty:Bool=false)->Bool { guard let a=v as? [String] else{return false};if nonempty&&a.isEmpty{return false};return a.allSatisfy{!$0.isEmpty} && a == Array(Set(a)).sorted() }
func arrEq(_ v:Any?,_ w:[String])->Bool { (v as? [String]) == w }
func valid(_ r:[String:Any])->Bool { switch s(r,"schema") {
case "entity-v3-evidence-object-v1": return evidence.contains(s(r,"evidence_type")) && hex64(r["content_sha256"]) && b(r,"signature_proves_attribution_not_objective_truth",true) && b(r,"immutable_evidence_record",true)
case "entity-v3-evidence-bound-claim-v1": return states.contains(s(r,"state")) && hex64(r["value_sha256"]) && refs(r["evidence_refs"]) && b(r,"claim_is_not_objective_truth",true) && b(r,"state_is_typed_not_absolute",true)
case "entity-v3-claim-status-transition-v1": return states.contains(s(r,"from_state")) && states.contains(s(r,"to_state")) && s(r,"from_state") != s(r,"to_state") && refs(r["evidence_refs"]) && b(r,"history_rewrite_prohibited",true) && b(r,"transition_does_not_establish_objective_truth",true)
case "entity-v3-attestation-authority-grant-v1": return refs(r["scopes"],true) && hex64(r["authority_evidence_sha256"]) && b(r,"attestation_authority_is_scope_limited",true) && b(r,"attestation_does_not_create_legal_truth",true)
case "entity-v3-attestation-v1": return !s(r,"grant_id").isEmpty && !s(r,"scope").isEmpty && refs(r["evidence_refs"],true) && b(r,"attestation_is_evidence_not_objective_truth",true)
case "entity-v3-external-reality-anchor-v1": return anchors.contains(s(r,"anchor_type")) && hex64(r["endpoint_descriptor_sha256"]) && b(r,"credentials_included",false) && b(r,"external_system_is_not_automatic_entity_authority",true)
case "entity-v3-external-reality-snapshot-v1": return hex64(r["record_sha256"]) && refs(r["verifier_evidence_refs"]) && b(r,"external_record_is_evidence_not_protocol_truth",true) && b(r,"record_may_be_contested_or_superseded",true)
case "entity-v3-causal-economic-node-v1": let o=obj(r["economic_observation"]); let obs=o.isEmpty || (b(o,"market_observation_is_not_accounting_fair_value",true) && b(o,"protocol_does_not_determine_legal_entitlement",true)); return nodes.contains(s(r,"node_type")) && refs(r["evidence_refs"]) && refs(r["event_refs"]) && obs
case "entity-v3-causal-economic-edge-v1": return edges.contains(s(r,"edge_type")) && s(r,"from_node_id") != s(r,"to_node_id") && refs(r["evidence_refs"],true) && refs(r["authority_refs"]) && refs(r["participation_rule_refs"]) && b(r,"causality_is_evidence_bound_not_assumed",true) && b(r,"economic_attribution_is_not_accounting_fair_value",true)
case "entity-v3-verifiable-reality-status-v1": return arrEq(r["core_primitives"],primitives) && b(r,"core_semantics_changed",false) && b(r,"market_engine_preserved",true) && b(r,"reality_claims_are_evidence_bound",true) && b(r,"cryptographic_verification_is_not_objective_truth",true) && b(r,"protocol_verification_is_not_objective_truth",true)
default: return false } }
func canonicalTranscript(_ rows:[[String:String]])->Data { let sorted=rows.sorted{$0["id"]!<$1["id"]!}; let text="["+sorted.map{"{\"actual\":"+String(data:try! JSONSerialization.data(withJSONObject:$0["actual"]!,options:[.fragmentsAllowed]),encoding:.utf8)!+",\"id\":"+String(data:try! JSONSerialization.data(withJSONObject:$0["id"]!,options:[.fragmentsAllowed]),encoding:.utf8)!+"}"}.joined(separator:",")+"]"; return Data(text.utf8) }
let raw=try Data(contentsOf:URL(fileURLWithPath:kitPath)); if sha(raw) != kitSHA { fatalError("sealed v3.3 kit SHA-256 mismatch") }
let kit=obj(try JSONSerialization.jsonObject(with:raw)); let cases=kit["cases"] as! [[String:Any]]; var rows:[[String:String]]=[]; var passed=0
for c in cases { let actual=valid(obj(c["record"])) ? "VALID":"INVALID"; if actual == s(c,"expect") { passed += 1 }; rows.append(["id":s(c,"id"),"actual":actual]) }
let result=sha(canonicalTranscript(rows)); let overall=passed==20 && result==expected && s(kit,"expected_result_sha256")==expected
let out:[String:Any]=["implementation":"swift","kit_sha256":kitSHA,"vectors_passed":passed,"vectors_total":20,"result_sha256":result,"expected_result_sha256":expected,"overall_valid":overall]
print(String(data:try JSONSerialization.data(withJSONObject:out,options:[.prettyPrinted,.sortedKeys]),encoding:.utf8)!); if !overall { exit(1) }
