// Seeds the one UE in config/ue.yaml (same schema as open5gs-dbctl add).
db = db.getSiblingDB("open5gs");
const ambr = { downlink: { value: NumberInt(1), unit: NumberInt(3) }, uplink: { value: NumberInt(1), unit: NumberInt(3) } };
db.subscribers.updateOne({ imsi: "999700000000001" }, { $set: {
  schema_version: NumberInt(1),
  imsi: "999700000000001",
  msisdn: [], imeisv: [], mme_host: [], mm_realm: [], purge_flag: [],
  slice: [{
    sst: NumberInt(1), default_indicator: true,
    session: [{
      name: "internet", type: NumberInt(3),
      qos: { index: NumberInt(9), arp: { priority_level: NumberInt(8), pre_emption_capability: NumberInt(1), pre_emption_vulnerability: NumberInt(1) } },
      ambr: ambr, pcc_rule: [], _id: new ObjectId(),
    }],
    _id: new ObjectId(),
  }],
  security: { k: "465B5CE8B199B49FAA5F0A2EE238A6BC", op: null, opc: "E8ED289DEBA952E4283B54E88E6183CA", amf: "8000" },
  ambr: ambr,
  access_restriction_data: 32, network_access_mode: 0, subscriber_status: 0,
  operator_determined_barring: 0, subscribed_rau_tau_timer: 12, __v: 0,
} }, { upsert: true });
