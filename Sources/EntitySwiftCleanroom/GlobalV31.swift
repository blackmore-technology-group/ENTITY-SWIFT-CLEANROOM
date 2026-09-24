import Foundation

let globalKinds:Set<String>=["SCHEMA","RIGHT","EVENT","CAPABILITY","ASSET_CLASS","TRUST_FRAMEWORK","DISPUTE_AUTHORITY","ATTESTATION_CLASS"]
let globalTopology:Set<String>=["CORE","REGIONAL","EDGE","SATELLITE","OFFLINE"]
let globalScarcity:Set<String>=["RIGHT","ENTITLEMENT","CAPACITY","DURATION","JURISDICTION","USAGE_QUANTITY","DERIVATION","PARTICIPATION","TRANSFERABILITY"]

func globalHex64(_ v:[String:Any],_ k:String)->Bool{
    let x=s(v,k);guard x.count==64 else{return false}
    return x.allSatisfy{ $0.isNumber || ($0>="a" && $0<="f") }
}
func globalStrings(_ a:[Any])->[String]{ a.compactMap{$0 as? String} }
func globalSortedUnique(_ a:[Any])->Bool{
    let x=globalStrings(a);return x.count==a.count && x == Array(Set(x)).sorted()
}

func validGlobalRecord(_ r:[String:Any])->Bool{
    switch s(r,"schema"){
    case "entity-v3-jurisdiction-profile-v1":
        if !b(r,"legal_effect_is_deployment_specific") { return false }
        return arr(r["rules"]).allSatisfy{ let x=obj($0);return ["ALLOW","REQUIRE","PROHIBIT"].contains(s(x,"effect")) && !arr(x["actions"]).isEmpty }
    case "entity-v3-semantic-term-v1": return globalKinds.contains(s(r,"kind")) && globalHex64(r,"definition_sha256") && s(r,"status")=="ACTIVE"
    case "entity-v3-topology-node-v1": return globalTopology.contains(s(r,"topology_class")) && b(r,"infrastructure_membership_is_not_sovereign_authority")
    case "entity-v3-purpose-bound-access-v1": return !arr(r["purposes"]).isEmpty && !arr(r["actions"]).isEmpty && i(r,"max_uses")>=0
    case "entity-v3-offline-envelope-v1": return globalHex64(r,"payload_sha256") && i(r,"sequence")>=0 && i(r,"expires_at_ms")>i(r,"created_at_ms")
    case "entity-v3-crypto-transition-v1": return b(r,"downgrade_after_transition_prohibited") && i(r,"old_retire_at_ms")>=i(r,"dual_sign_from_ms")
    case "entity-v3-data-economic-capital-v1": return b(r,"information_bytes_are_not_declared_scarce") && globalHex64(r,"provenance_root") && globalHex64(r,"content_sha256")
    case "entity-v3-bounded-economic-interest-v1":
        let actions=arr(r["actions"]), scarcity=globalStrings(arr(r["scarcity_sources"]))
        let p=i(r,"participation_bps")
        return !actions.isEmpty && globalSortedUnique(actions) && scarcity.contains("RIGHT") && scarcity.allSatisfy{globalScarcity.contains($0)} && b(r,"underlying_information_remains_nonrival") && p>=0 && p<=10000
    default: return false
    }
}

func verifyGlobalChecksums(_ root:String)->Bool{
    guard let text=try? String(contentsOfFile:root+"/SHA256SUMS.txt",encoding:.utf8) else{return false}
    for raw in text.replacingOccurrences(of:"\u{feff}",with:"").split(separator:"\n"){
        let line=String(raw);if line.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty{continue}
        guard let r=line.range(of:"  ") else{return false};let expected=String(line[..<r.lowerBound]).trimmingCharacters(in:.whitespacesAndNewlines);let rel=String(line[r.upperBound...]).trimmingCharacters(in:.whitespacesAndNewlines)
        guard let data=try? Data(contentsOf:URL(fileURLWithPath:root+"/"+rel)), sha256(data)==expected else{return false}
    }
    return true
}

func runGlobalV31() throws -> [String:Any]{
    let root=URL(fileURLWithPath:FileManager.default.currentDirectoryPath).appendingPathComponent("global-conformance-kit").path
    let checksums=verifyGlobalChecksums(root)
    let profile=obj(try load(root+"/ENTITY_GLOBAL_CLEANROOM_PROFILE.json"))
    let manifest=obj(try load(root+"/vectors/VECTOR_MANIFEST.json"))
    var rows:[[String:Any]]=[]
    for ee in arr(manifest["vectors"]){
        let e=obj(ee), file=s(e,"file"), payload=obj(try load(root+"/vectors/"+file))
        let accepted=validGlobalRecord(obj(payload["record"])), expected=s(payload,"expect")
        rows.append(["name":String(file.dropLast(5)),"accepted":accepted,"expected":expected,"ok":accepted==(expected=="VALID")])
    }
    rows.sort{ s($0,"name") < s($1,"name") }
    let summary:[String:Any]=["schema":"entity-v3.1-global-cleanroom-result-v1","profile":"ENTITY-GLOBAL-INFRASTRUCTURE","doctrine_invariants":profile["doctrine_invariants"]!,"vectors":rows]
    let result=sha256(try jsonData(summary));let passed=rows.filter{b($0,"ok")}.count;let valid=rows.filter{b($0,"accepted")}.count
    let overall=checksums && passed==rows.count && result==s(profile,"expected_result_sha256") && Int64(valid)==i(profile,"valid_vectors") && Int64(rows.count-valid)==i(profile,"invalid_vectors")
    return ["implementation":"swift","checksums_pass":checksums,"vectors_passed":passed,"vectors_total":rows.count,"result_sha256":result,"expected_result_sha256":s(profile,"expected_result_sha256"),"doctrine_invariants":profile["doctrine_invariants"]!,"overall_valid":overall,"results":rows]
}
