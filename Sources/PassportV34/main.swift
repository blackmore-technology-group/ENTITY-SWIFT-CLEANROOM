import Foundation
import Crypto

let kitPath = "passport-conformance-kit-v342/ENTITY_V3_4_2_GLOBAL_PASSPORT_CLEANROOM_KIT.min.json"
let kitSHA = "ced70113f1d153627eb972b11adbf20e502ed086e0b13e8abf1dc5adc4c2e716"
let expected = "45af773554a7191c1b49a75c636a1106afb1de36d788bb00d7af56097b8d1b0e"
let core = ["ENTITY","AUTHORITY","RIGHT","EVENT","VALUE"]
let kinds:Set<String> = ["GLOBAL","JURISDICTION","INDUSTRY","DOMAIN","PRIVACY","TRUST","DISCLOSURE"]
func sha(_ data:Data)->String { SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined() }
func obj(_ v:Any?)->[String:Any] { v as? [String:Any] ?? [:] }
func s(_ r:[String:Any],_ k:String)->String { r[k] as? String ?? "" }
func b(_ r:[String:Any],_ k:String,_ w:Bool)->Bool { (r[k] as? Bool) == w }
func hex64(_ v:Any?)->Bool { guard let x=v as? String,x.count==64 else{return false};return x.allSatisfy{$0.isNumber || ("abcdef".contains($0))} }
func arrEq(_ v:Any?,_ w:[String])->Bool { (v as? [String]) == w }
func btdu(_ r:[String:Any])->Bool { s(r,"schema")=="entity-btdu-passport-binding-v1" && s(r,"btdu_version")=="3.4.2" && !s(r,"universe_root").isEmpty && !s(r,"object_ref").isEmpty && hex64(r["content_sha256"]) && !s(r,"sovereign_entity_id").isEmpty && b(r,"protocol_origin_is_not_asset_provenance",true) && b(r,"topology_does_not_create_ownership",true) && b(r,"topology_does_not_create_economic_entitlement",true) && (r["automatic_protocol_royalty_bps"] as? Int)==0 }
func stack(_ r:[String:Any])->Bool { guard let refs=r["profile_refs"] as? [String],!refs.isEmpty,refs.contains("entity-profile:global@1.0"),let hs=r["profile_hashes"] as? [String],hs.count==refs.count else{return false};return hs.allSatisfy{hex64($0)} && b(r,"fail_closed",true) && b(r,"profile_composition_does_not_create_authority",true) && b(r,"standards_mapping_is_not_normative_equivalence",true) }
func valid(_ r:[String:Any])->Bool { switch s(r,"schema") {
case "entity-v3-global-passport-profile-status-v1": return arrEq(r["core_primitives"],core) && b(r,"core_semantics_changed",false) && b(r,"market_engine_preserved",true) && b(r,"one_passport_many_profiles",true) && b(r,"evidence_truth_boundary_preserved",true)
case "entity-v3-global-profile-v1": return !s(r,"profile_ref").isEmpty && kinds.contains(s(r,"kind")) && hex64(r["schema_sha256"]) && b(r,"profile_is_not_authority",true) && b(r,"standards_mapping_is_not_normative_equivalence",true) && (!s(r,"profile_id").uppercased().contains("DEFENCE") || b(r,"public_unclassified",true))
case "entity-v3-profile-stack-resolution-v1": return stack(r)
case "entity-v3-global-passport-v1": let e=obj(r["economic_state"]); guard let amount=e["amount_units"] as? Int,amount>=0,let ms=r["standards_mappings"] as? [[String:Any]],ms.allSatisfy({b($0,"normative_equivalence_claimed",false)}) else{return false}; return (r["btdu_binding"] == nil || btdu(obj(r["btdu_binding"]))) && arrEq(r["core_primitives"],core) && !s(r,"rights_passport_id").isEmpty && hex64(r["rights_passport_sha256"]) && stack(obj(r["profile_stack"])) && b(r,"one_passport_many_profiles",true) && b(r,"profile_composition_does_not_create_authority",true) && b(r,"standards_mapping_is_not_normative_equivalence",true) && b(r,"evidence_does_not_establish_objective_truth",true) && b(r,"legal_effect_is_deployment_specific",true) && b(r,"underlying_information_remains_nonrival",true) && b(e,"market_observation_is_not_accounting_fair_value",true)
case "entity-v3-continuous-ingest-result-v1": guard let files=r["files"] as? Int else{return false}; return files>=0 && hex64(r["inventory_sha256"]) && b(r,"content_addressed",true) && b(r,"custody_is_not_authority",true) && b(r,"economic_value_invented",false)
default:return false } }
func canonString(_ value:String)->String { String(data:try! JSONSerialization.data(withJSONObject:value,options:[.fragmentsAllowed]),encoding:.utf8)! }
func canonicalTranscript(_ rows:[[String:String]])->Data { let sorted=rows.sorted{$0["id"]!<$1["id"]!};let text="["+sorted.map{"{\"actual\":"+canonString($0["actual"]!)+",\"id\":"+canonString($0["id"]!)+"}"}.joined(separator:",")+"]";return Data(text.utf8) }
let raw=try Data(contentsOf:URL(fileURLWithPath:kitPath));if sha(raw) != kitSHA { fatalError("sealed v3.4 kit SHA-256 mismatch") }
let kit=obj(try JSONSerialization.jsonObject(with:raw));let cases=(kit["cases"] as! [[String:Any]]).sorted{s($0,"id")<s($1,"id")};var rows:[[String:String]]=[];var passed=0
for c in cases { let actual=valid(obj(c["record"])) ? "VALID":"INVALID";if actual==s(c,"expect"){passed+=1};rows.append(["id":s(c,"id"),"actual":actual]) }
let result=sha(canonicalTranscript(rows));let overall=passed==26 && result==expected && s(kit,"expected_result_sha256")==expected
let out:[String:Any]=["implementation":"swift","kit_sha256":kitSHA,"vectors_passed":passed,"vectors_total":26,"result_sha256":result,"expected_result_sha256":expected,"overall_valid":overall]
print(String(data:try JSONSerialization.data(withJSONObject:out,options:[.prettyPrinted,.sortedKeys]),encoding:.utf8)!);if !overall { exit(1) }
