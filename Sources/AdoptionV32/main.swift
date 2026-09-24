import Foundation
import Crypto

let kitPath = "adoption-conformance-kit/ENTITY_V3_2_ADOPTION_CLEANROOM_KIT.min.json"
let kitSHA = "44e7a00f910c89aced3b3c1b5e9cba486809ca313e9bfb4b7bc9266095c10c14"
let expected = "1eb59e09ab08da86bfd8584df4a64ba331f7bbbce3d236b9b94f351606c90e18"
let primitives = ["ENTITY","AUTHORITY","RIGHT","EVENT","VALUE"]
let lifecycle = ["DCO","INSTRUMENT","LISTING","DISCLOSURE","ORDER_RFQ_AUCTION","PRICE_DISCOVERY","TRADE","CLEARING","SETTLEMENT","ENTITLEMENT","USAGE","DERIVED_OUTPUT","ECONOMIC_CONSEQUENCE"]
let providers:Set<String> = ["AWS_S3","AZURE_BLOB","GOOGLE_CLOUD_STORAGE","SNOWFLAKE","DATABRICKS","POSTGRESQL","SQL_SERVER","LOCAL_FILESYSTEM","HTTP_API"]
let standards:Set<String> = ["ODRL","W3C_VC","DID","GAIA_X","IDS"]
func sha(_ data:Data)->String{SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
func dict(_ x:Any?)->[String:Any]{x as? [String:Any] ?? [:]}
func str(_ r:[String:Any],_ k:String)->String{r[k] as? String ?? ""}
func boo(_ r:[String:Any],_ k:String,_ w:Bool)->Bool{(r[k] as? Bool)==w}
func hex64(_ x:Any?)->Bool{guard let s=x as? String,s.count==64 else{return false};return s.allSatisfy{$0.isNumber || ("a"..."f").contains(String($0))}}
func strs(_ x:Any?)->[String]?{guard let a=x as? [Any] else{return nil};let z=a.compactMap{$0 as? String};return z.count==a.count ? z:nil}
func arrEq(_ x:Any?,_ want:[String])->Bool{strs(x)==want}
func rules(_ x:Any?)->Bool{guard let a=x as? [Any],!a.isEmpty else{return false};for y in a{let q=dict(y);if !["ALLOW","REQUIRE","PROHIBIT"].contains(str(q,"effect")){return false};guard let xs=strs(q["actions"]),!xs.isEmpty else{return false};if xs != Array(Set(xs)).sorted() || xs.contains(where:{$0.isEmpty || $0 != $0.uppercased()}){return false}};return true}
func valid(_ r:[String:Any])->Bool{switch str(r,"schema"){
case "entity-v3-rights-passport-v1":return arrEq(r["core_primitives"],primitives)&&rules(r["rights"])&&boo(r,"provider_custody_is_not_authority",true)&&boo(r,"underlying_data_not_silently_transferred",true)&&boo(r,"legal_effect_is_deployment_specific",true)
case "entity-v3-custody-locator-v1":return providers.contains(str(r,"provider"))&&hex64(r["content_sha256"])&&boo(r,"provider_is_authority",false)&&boo(r,"credentials_included",false)&&boo(r,"entity_identity_changes_with_provider",false)
case "entity-v3-standards-mapping-v1":return standards.contains(str(r,"source_standard"))&&hex64(r["source_sha256"])&&boo(r,"silent_semantic_equivalence",false)&&boo(r,"external_standard_is_not_entity_authority",true)
case "entity-v3-external-credential-evidence-v1":return str(r,"source_standard")=="W3C_VC"&&hex64(r["credential_sha256"])&&boo(r,"credential_is_evidence_not_entity_authority",true)
case "entity-v3-resolver-deployment-v1":return str(r,"mode")=="FEDERATED"&&(r["minimum_resolvers"] as? Int ?? 0)>=2&&boo(r,"resolver_is_not_authority",true)&&boo(r,"single_provider_dependency_prohibited",true)&&boo(r,"fail_closed",true)
case "entity-v3-exchange-adoption-profile-v1":return boo(r,"market_engine_preserved",true)&&boo(r,"rights_are_traded_not_bytes",true)&&arrEq(r["market_lifecycle"],lifecycle)
case "entity-v3-adoption-profile-status-v1":return arrEq(r["core_primitives"],primitives)&&boo(r,"core_semantics_changed",false)&&boo(r,"market_engine_preserved",true)
case "entity-v3-legal-classification-assertion-v1":return !str(r,"asserted_by").isEmpty && !str(r,"classification").isEmpty && boo(r,"classification_is_assertion_not_protocol_legal_truth",true)
default:return false}}
func quoted(_ s:String)->String{String(data:try! JSONSerialization.data(withJSONObject:[s]),encoding:.utf8)!.dropFirst().dropLast().description}
func canonical(_ x:Any)->String{if let d=x as? [String:Any]{return "{"+d.keys.sorted().map{quoted($0)+":"+canonical(d[$0]!)}.joined(separator:",")+"}"};if let a=x as? [Any]{return "["+a.map(canonical).joined(separator:",")+"]"};if let s=x as? String{return quoted(s)};if let b=x as? Bool{return b ? "true":"false"};if x is NSNull{return "null"};return String(describing:x)}
let raw=try Data(contentsOf:URL(fileURLWithPath:kitPath));guard sha(raw)==kitSHA else{fatalError("sealed kit SHA-256 mismatch")};let kit=try JSONSerialization.jsonObject(with:raw) as! [String:Any];let vectors=kit["vectors"] as! [[String:Any]];var rows=[[String:Any]]();var passed=0
for v in vectors{let accepted=valid(dict(v["record"]));let exp=str(v,"expect");let ok=accepted==(exp=="VALID");if ok{passed+=1};rows.append(["name":str(v,"name"),"accepted":accepted,"expected":exp,"ok":ok])};rows.sort{str($0,"name")<str($1,"name")};let profile=dict(kit["profile"]);let summary:[String:Any]=["schema":"entity-v3.2-adoption-cleanroom-result-v1","profile":"ENTITY-ADOPTION-LAYER","adoption_invariants":profile["adoption_invariants"]!,"vectors":rows];let result=sha(canonical(summary).data(using:.utf8)!);let overall=passed==16&&result==expected;let out:[String:Any]=["implementation":"swift","kit_sha256":kitSHA,"vectors_passed":passed,"vectors_total":16,"result_sha256":result,"expected_result_sha256":expected,"overall_valid":overall];let data=try JSONSerialization.data(withJSONObject:out,options:[.prettyPrinted,.sortedKeys]);print(String(data:data,encoding:.utf8)!);if !overall{exit(1)}
