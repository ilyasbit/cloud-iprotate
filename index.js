const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const fs = require("fs");
const morgan = require("morgan");
const axios = require("axios");
const { SocksProxyAgent } = require("socks-proxy-agent");
const tencentcloud = require("tencentcloud-sdk-nodejs");
const { DefaultAzureCredential } = require("@azure/identity");
const { NetworkManagementClient } = require("@azure/arm-network");

const {
  EC2Client,
  AllocateAddressCommand,
  DisassociateAddressCommand,
  AssociateAddressCommand,
  DescribeAddressesCommand,
  ReleaseAddressCommand,
  DescribeInstancesCommand,
} = require("@aws-sdk/client-ec2");
const ConfigParser = require("configparser");
const { exec } = require("child_process");
app.use(bodyParser.json());
app.use(morgan("combined"));
const config = new ConfigParser();
config.read("config.conf");
const prefix = config.get("api", "prefix");
const appPort = config.get("api", "port");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
//clearup runningprocess.txt file
fs.writeFile("runningprocess.txt", "", function (err) {
  if (err) throw err;
});

app.listen(appPort, "0.0.0.0", () => {
  console.log(`Listening on port ${appPort}`);
});

async function newIpAws(serverConfig) {
  const accessKey = serverConfig.accessKey;
  const secretKey = serverConfig.secretKey;
  const instanceId = serverConfig.instanceId;
  const region = serverConfig.region;
  const ec2 = new EC2Client({
    region: region,
    credentials: {
      accessKeyId: accessKey,
      secretAccessKey: secretKey,
    },
  });
  async function disassociateAndRelease() {
    //list all elastic ip with tag instance=instanceId
    try {
      const command = new DescribeAddressesCommand({
        Filters: [
          {
            Name: "tag:instance",
            Values: [instanceId],
          },
        ],
      });
      const response = await ec2.send(command);
      if (response.Addresses.length > 0) {
        console.log(response);
        for (let i = 0; i < response.Addresses.length; i++) {
          try {
            const command = new DisassociateAddressCommand({
              AssociationId: response.Addresses[i].AssociationId,
            });
            await ec2.send(command);
          } catch (err) {}
          try {
            const command2 = new ReleaseAddressCommand({
              AllocationId: response.Addresses[i].AllocationId,
            });
            await ec2.send(command2);
          } catch (err) {}
        }
      }
    } catch (err) {
      console.error(err);
    }
  }

  async function getInstanceIp() {
    try {
      const command = new DescribeInstancesCommand({
        InstanceIds: [instanceId],
      });
      const response = await ec2.send(command);
      return response.Reservations[0].Instances[0].PublicIpAddress;
    } catch (err) {
      console.error(err);
    }
  }
  const oldIp = await getInstanceIp();
  async function allocateElasticIp() {
    try {
      const command = new AllocateAddressCommand({
        TagSpecifications: [
          {
            ResourceType: "elastic-ip",
            Tags: [{ Key: "instance", Value: instanceId }],
          },
        ],
      });
      const response = await ec2.send(command);
      return {
        elasticIp: response.PublicIp,
        allocationId: response.AllocationId,
      };
    } catch (err) {
      console.error(err);
    }
  }
  await disassociateAndRelease();
  const allocateIp = await allocateElasticIp();
  async function associateIp() {
    try {
      const command = new AssociateAddressCommand({
        InstanceId: instanceId,
        PublicIp: allocateIp.elasticIp,
      });
      const response = await ec2.send(command);
      return response;
    } catch (err) {
      console.error(err);
    }
  }
  const asassociate = await associateIp();
  await new Promise((resolve) => setTimeout(resolve, 1500));
  async function disassociateIp() {
    try {
      const command = new DisassociateAddressCommand({
        PublicIp: allocateIp.elasticIp,
      });
      const response = await ec2.send(command);
      return response;
    } catch (err) {
      console.error(err);
    }
  }
  disassociateIp();
  async function releaseIp() {
    try {
      const command = new ReleaseAddressCommand({
        AllocationId: allocateIp.allocationId,
      });
      const response = await ec2.send(command);
      return response;
    } catch (err) {
      console.error(err);
    }
  }
  releaseIp();
  await new Promise((resolve) => setTimeout(resolve, 1500));
  const newIp = await getInstanceIp();
  return { oldIp: oldIp, newIp: newIp };
}

async function newIpAzure(serverConfig) {
  process.env.AZURE_CLIENT_ID = serverConfig.clientId;
  process.env.AZURE_CLIENT_SECRET = serverConfig.clientSecret;
  process.env.AZURE_SUBSCRIPTION_ID = serverConfig.subscriptionId;
  process.env.AZURE_TENANT_ID = serverConfig.tenantId;
  const AZURE_CLIENT_ID = process.env.AZURE_CLIENT_ID;
  const AZURE_CLIENT_SECRET = process.env.AZURE_CLIENT_SECRET;
  const AZURE_SUBSCRIPTION_ID = process.env.AZURE_SUBSCRIPTION_ID;
  const AZURE_TENANT_ID = process.env.AZURE_TENANT_ID;
  const resourceGroupName = serverConfig.resourceGroupName;
  const publicIpName = serverConfig.publicIpName;
  const nicName = serverConfig.nicName;

  const credential = new DefaultAzureCredential({
    clientId: AZURE_CLIENT_ID,
    clientSecret: AZURE_CLIENT_SECRET,
    tenantId: AZURE_TENANT_ID,
  });

  const networkClient = new NetworkManagementClient(
    credential,
    AZURE_SUBSCRIPTION_ID
  );

  async function getNic() {
    const nic = await networkClient.networkInterfaces.get(
      resourceGroupName,
      nicName
    );
    return nic;
  }

  async function getIpDetail() {
    const ip = await networkClient.publicIPAddresses.get(
      resourceGroupName,
      publicIpName
    );
    return ip;
  }

  async function disassociate(nic) {
    nic.ipConfigurations[0].publicIPAddress = null;
    const disassociate =
      await networkClient.networkInterfaces.beginCreateOrUpdate(
        resourceGroupName,
        nicName,
        nic
      );
    return disassociate;
  }

  async function associate(nic, ip) {
    nic.ipConfigurations[0].publicIPAddress = ip;

    await networkClient.networkInterfaces.beginCreateOrUpdate(
      resourceGroupName,
      nicName,
      nic
    );
  }
  let oldIp;
  let ip, nic;
  let retries = 0;
  let max = 10;
  while (true) {
    try {
      [ip, nic] = await Promise.all([getIpDetail(), getNic()]);
      break;
    } catch (err) {
      retries++;
      if (retries < max) {
        continue;
      } else if (retries === max) {
        throw new Error("Failed to get ip or nic on first action");
      }
    }
  }

  await sleep(500);
  oldIp = ip.ipAddress;
  if (!oldIp) {
    oldIp = null;
  }
  await disassociate(nic);
  await sleep(500);
  nic = await getNic();
  retries = 0;
  max = 10;
  while (true) {
    if (!nic.ipConfigurations[0].publicIPAddress) {
      try {
        await disassociate(nic);
      } catch (err) {}
      break;
    } else {
      try {
        await disassociate(nic);
        nic = await getNic();
        await sleep(500);
        retries++;
        if (retries < max) {
          continue;
        } else if (retries === max) {
          throw new Error("Failed to disassociate ip");
        }
      } catch (err) {}
    }
  }
  retries = 0;
  max = 10;
  while (true) {
    try {
      [ip, nic] = await Promise.all([getIpDetail(), getNic()]);
      break;
    } catch (err) {
      retries++;
      if (retries < max) {
        continue;
      } else if (retries === max) {
        throw new Error("Failed to get ip or nic on seconds action");
      }
    }
  }
  await sleep(500);
  retries = 0;
  max = 10;
  while (true) {
    try {
      await associate(nic, ip);
      await sleep(500);
      break;
    } catch (err) {
      retries++;
      if (retries < max) {
        continue;
      } else if (retries === max) {
        throw new Error("Failed to associate ip");
      }
    }
  }
  retries = 0;
  max = 10;
  while (true) {
    try {
      [ip, nic] = await Promise.all([getIpDetail(), getNic()]);
      break;
    } catch (err) {
      retries++;
      if (retries < max) {
        continue;
      } else if (retries === max) {
        throw new Error("Failed to get ip or nic on third action");
      }
    }
  }
  retries = 0;
  max = 30;
  while (true) {
    if (!ip.ipAddress || ip.ipAddress === oldIp) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      ip = await getIpDetail();
      retries++;
      if (retries < max) {
        continue;
      } else {
        break;
      }
    } else {
      break;
    }
  }
  const newIp = ip.ipAddress;
  if (!newIp) {
    throw new Error("Failed to get new IP");
  }
  return { oldIp: oldIp, newIp: newIp };
}

async function newIpTencent(serverConfig) {
  const CvmClient = tencentcloud.cvm.v20170312.Client;
  const secretId = serverConfig.secretId;
  const secretKey = serverConfig.secretKey;
  const region = serverConfig.region;
  const instanceId = serverConfig.instanceId;
  const clientConfig = {
    credential: {
      secretId: secretId,
      secretKey: secretKey,
    },
    region: region,
    profile: {
      httpProfile: {
        endpoint: "cvm.tencentcloudapi.com",
      },
    },
  };
  const client = new CvmClient(clientConfig);
  const params = {
    InstanceIds: [instanceId],
  };
  const stopParams = {
    InstanceIds: [`${instanceId}`],
    StopType: "HARD",
    StoppedMode: "STOP_CHARGING",
  };
  let instanceDescribed = await client.DescribeInstances(params);
  let oldIp = "";
  if (
    instanceDescribed.InstanceSet[0].PublicIpAddresses == null ||
    instanceDescribed.InstanceSet[0].PublicIpAddresses.length === 0
  ) {
    oldIp = "";
  } else {
    oldIp = instanceDescribed.InstanceSet[0].PublicIpAddresses[0];
  }
  instanceDescribed = await client.DescribeInstances(params);
  if (instanceDescribed.InstanceSet[0].InstanceState === "RUNNING") {
    const stopData = await client.StopInstances(stopParams).then(async () => {
      await new Promise((resolve) => setTimeout(resolve, 2000));
      instanceDescribed = await client.DescribeInstances(params);
      while (true) {
        if (
          instanceDescribed.InstanceSet[0].InstanceState == "STARTING" ||
          instanceDescribed.InstanceSet[0].InstanceState == "STOPPING"
        ) {
          await new Promise((resolve) => setTimeout(resolve, 2000));
          instanceDescribed = await client.DescribeInstances(params);
        } else {
          break;
        }
      }
      await client.StartInstances(params);
      while (true) {
        if (instanceDescribed.InstanceSet[0].InstanceState == "RUNNING") {
          publicIp = instanceDescribed.InstanceSet[0].PublicIpAddresses[0];
          break;
        } else {
          instanceDescribed = await client.DescribeInstances(params);
        }
      }
    });
  } else if (instanceDescribed.InstanceSet[0].InstanceState === "STOPPED") {
    await client.StartInstances(params);
    while (true) {
      if (instanceDescribed.InstanceSet[0].InstanceState == "RUNNING") {
        publicIp = instanceDescribed.InstanceSet[0].PublicIpAddresses[0];
        break;
      } else {
        instanceDescribed = await client.DescribeInstances(params);
      }
    }
  }
  return { oldIp: oldIp, newIp: publicIp };
}

async function parseConfig() {
  config.read("config.conf");
  const confList = config.sections();
  let tencentConfigList = [];
  let azureConfigList = [];
  let awsConfigList = [];
  let cloudflareConfig = {};
  let apiConfig = {};
  for (let i = 0; i < confList.length; i++) {
    const configName = confList[i];
    const configType = config.get(confList[i], "type");
    if (configType == "tencent") {
      const secretId = config.get(confList[i], "secretId");
      const secretKey = config.get(confList[i], "secretKey");
      const region = config.get(confList[i], "region");
      const instanceId = config.get(confList[i], "instanceId");
      const socks5Port = config.get(confList[i], "socks5Port");
      const httpPort = config.get(confList[i], "httpPort");
      tencentConfigList.push({
        configName: configName,
        secretId: secretId,
        secretKey: secretKey,
        region: region,
        instanceId: instanceId,
        socks5Port: socks5Port,
        httpPort: httpPort,
      });
    } else if (configType == "cloudflare") {
      const email = config.get(confList[i], "email");
      const token = config.get(confList[i], "token");
      const domain = config.get(confList[i], "domain");
      cloudflareConfig.email = email;
      cloudflareConfig.token = token;
      cloudflareConfig.domain = domain;
    } else if (configType == "api") {
      const prefix = config.get(confList[i], "prefix");
      const port = config.get(confList[i], "port");
      const local_ip = config.get(confList[i], "local_ip");
      const key = config.get(confList[i], "key");
      apiConfig.prefix = prefix;
      apiConfig.port = port;
      apiConfig.local_ip = local_ip;
      apiConfig.key = key;
    } else if (configType == "azure") {
      const socks5Port = config.get(confList[i], "socks5Port");
      const httpPort = config.get(confList[i], "httpPort");
      const clientId = config.get(confList[i], "clientId");
      const clientSecret = config.get(confList[i], "clientSecret");
      const tenantId = config.get(confList[i], "tenantId");
      const subscriptionId = config.get(confList[i], "subscriptionId");
      const resourceGroupName = config.get(confList[i], "resourceGroupName");
      const publicIpName = config.get(confList[i], "publicIpName");
      const ipConfigName = config.get(confList[i], "ipConfigName");
      const nicName = config.get(confList[i], "nicName");
      const vmName = config.get(confList[i], "vmName");
      azureConfigList.push({
        configName: configName,
        socks5Port: socks5Port,
        httpPort: httpPort,
        clientId: clientId,
        clientSecret: clientSecret,
        tenantId: tenantId,
        subscriptionId: subscriptionId,
        resourceGroupName: resourceGroupName,
        publicIpName: publicIpName,
        ipConfigName: ipConfigName,
        nicName: nicName,
        vmName: vmName,
      });
    } else if (configType == "aws") {
      const accessKey = config.get(confList[i], "accessKey");
      const secretKey = config.get(confList[i], "secretKey");
      const instanceId = config.get(confList[i], "instanceId");
      const region = config.get(confList[i], "region");
      const socks5Port = config.get(confList[i], "socks5Port");
      const httpPort = config.get(confList[i], "httpPort");
      awsConfigList.push({
        configName: configName,
        accessKey: accessKey,
        secretKey: secretKey,
        instanceId: instanceId,
        region: region,
        socks5Port: socks5Port,
        httpPort: httpPort,
      });
    }
  }
  return {
    configs: {
      api: apiConfig,
      cloudflare: cloudflareConfig,
      tencent: tencentConfigList,
      azure: azureConfigList,
      aws: awsConfigList,
    },
  };
}

app.get(`/${prefix}/describe`, async (req, res) => {
  try {
    const { configs } = await parseConfig();
    const tencentConfigList = configs.tencent;
    let instanceDetails = [];
    await Promise.all(
      tencentConfigList.map(async (config) => {
        const CvmClient = tencentcloud.cvm.v20170312.Client;
        const clientConfig = {
          credential: {
            secretId: config.secretId,
            secretKey: config.secretKey,
          },
          region: config.region,
          profile: {
            httpProfile: {
              endpoint: "cvm.tencentcloudapi.com",
            },
          },
        };
        const client = new CvmClient(clientConfig);
        const params = {
          InstanceIds: [`${config.instanceId}`],
        };
        const instanceData = await client.DescribeInstances(params).then(
          (data) => {
            return data.InstanceSet[0];
          },
          (err) => {
            console.error("error", err);
          }
        );
        instanceDetails.push(instanceData);
      })
    );
    return res.status(200).json({ success: true, instanceDetails });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.get(`/${prefix}/reset2/:configName`, async (req, res) => {
  try {
    const { configs } = await parseConfig();
    const apiConfig = configs.api;
    const cloudflareConfig = configs.cloudflare;
    const domain = cloudflareConfig.domain;
    const email = cloudflareConfig.email;
    const token = cloudflareConfig.token;
    const local_ip = apiConfig.local_ip;
    const configName = req.params.configName;
    const host = `${configName}.${domain}`;
    const cf = require("cloudflare")({
      email: email,
      key: token,
    });
    const configType = config.get(configName, "type");
    if (!configType) {
      return res
        .status(400)
        .json({ success: false, error: "config not found" });
    }
    //stop service sslocal_$configName
    exec(`systemctl stop sslocal_${configName}`, (err, stdout, stderr) => {
      if (err) {
        console.error(`Error stopping service: ${err}`);
        return;
      }
      console.log(stdout);
      console.log(stderr);
    });

    let result;
    let serverConfig;
    if (configType == "tencent") {
      serverConfig = configs.tencent.find(
        (config) => config.configName == configName
      );
      result = await newIpTencent(serverConfig);
    } else if (configType == "azure") {
      //remove configName from runningprocess.txt
      runningProcess = fs.readFileSync("runningprocess.txt", "utf8");
      runningProcessArray = runningProcess.split("\n");
      runningProcessIndex = runningProcessArray.findIndex(
        (line) => line == configName
      );
      runningProcessArray.splice(runningProcessIndex, 1);
      const newRunningProcess = runningProcessArray.join("\n");
      serverConfig = configs.azure.find(
        (config) => config.configName == configName
      );
      result = await newIpAzure(serverConfig);
    } else if (configType == "aws") {
      serverConfig = configs.aws.find(
        (config) => config.configName == configName
      );
      result = await newIpAws(serverConfig);
    }
    const socks5Port = serverConfig.socks5Port;
    const httpPort = serverConfig.httpPort;
    const publicIp = result.newIp;
    //check if host exist on /etc/hosts, if yes delete the line cotaint host
    const hosts = fs.readFileSync("/etc/hosts", "utf8");
    const hostsArray = hosts.split("\n");
    const hostIndex = hostsArray.findIndex((line) => line.includes(host));
    if (hostIndex != -1) {
      hostsArray.splice(hostIndex, 1);
      const newHosts = hostsArray.join("\n");
      fs.writeFileSync("/etc/hosts", newHosts);
    }
    //add host to /etc/hosts
    fs.appendFileSync("/etc/hosts", `${publicIp} ${host}\n`);
    //update cloudflare dns record
    console.log(
      `profile: ${configName}, old ip: ${result.oldIp}, new ip: ${result.newIp}`
    );
    const zoneId = await cf.zones.browse().then((data) => {
      const zone = data.result.find((zone) => zone.name == domain);
      return zone.id;
    });
    //check if dns record for host exist, if not create one, if yes update it
    const dnsRecord = await cf.dnsRecords.browse(zoneId).then((data) => {
      const record = data.result.find((record) => record.name == host);
      return record;
    });
    if (dnsRecord == undefined) {
      await cf.dnsRecords.add(zoneId, {
        type: "A",
        name: host,
        content: publicIp,
        ttl: 1,
        proxied: false,
      });
    } else {
      await cf.dnsRecords.edit(zoneId, dnsRecord.id, {
        type: "A",
        name: host,
        content: publicIp,
        ttl: 1,
        proxied: false,
      });
    }

    const configPath = `/etc/shadowsocks/config_${configName}.json`;
    const configTemplate = fs.readFileSync("configtemplate.json", "utf8");
    const configTemplateJson = JSON.parse(configTemplate);
    configTemplateJson.server = host;
    configTemplateJson.server_port = 8388;
    configTemplateJson.password = "Pass";
    configTemplateJson.method = "aes-128-gcm";
    configTemplateJson.mode = "tcp_and_udp";
    configTemplateJson.local_address = local_ip;
    configTemplateJson.local_port = parseInt(socks5Port);
    configTemplateJson.locals[0].local_address = local_ip;
    configTemplateJson.locals[0].local_port = parseInt(httpPort);
    fs.writeFileSync(configPath, JSON.stringify(configTemplateJson));

    const servicePath = `/etc/systemd/system/sslocal_${configName}.service`;
    const serviceTemplate = fs.readFileSync("service_template.service", "utf8");

    const serviceTemplateArray = serviceTemplate.split("\n");
    const serviceTemplateIndex = serviceTemplateArray.findIndex((line) =>
      line.includes("ExecStart")
    );
    serviceTemplateArray[
      serviceTemplateIndex
    ] = `ExecStart=/usr/local/bin/sslocal -c /etc/shadowsocks/config_${configName}.json`;
    const newServiceTemplate = serviceTemplateArray.join("\n");
    fs.writeFileSync(servicePath, newServiceTemplate);
    //enable and start sslocal_$configName.service
    await exec(`systemctl daemon-reload`);
    await exec(`systemctl start sslocal_${configName}.service`);
    let retry = 0;
    let maxRetry = 10;
    while (true) {
      try {
        //check socks5://localhost:socks5Port to fake.chiacloud.farm/ip using axios, if response.data == publicIp, break
        const socks5Url = `socks5://localhost:${socks5Port}`;
        const agent = new SocksProxyAgent(socks5Url);

        const response = await axios.request({
          url: "http://fake.chiacloud.farm/ip",
          method: "GET",
          httpsAgent: agent,
          httpAgent: agent,
          timeout: 1000,
        });
        if (response.data == publicIp) {
          break;
        }
        if (retry >= maxRetry) {
          throw new Error("retry proxy connection exceed maxRetry");
        }
      } catch (err) {
        await sleep(500);
        retry++;
        continue;
      }
    }
    return res.status(200).json({ success: true, result });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.get(`/${prefix}/reset/:configName`, async (req, res) => {
  const configName = req.params.configName;
  console.log(`hit reset2 ${configName}`);
  try {
    const { configs } = await parseConfig();
    const apiConfig = configs.api;
    const cloudflareConfig = configs.cloudflare;
    const domain = cloudflareConfig.domain;
    const email = cloudflareConfig.email;
    const token = cloudflareConfig.token;
    const local_ip = apiConfig.local_ip;
    const host = `${configName}.${domain}`;
    const configType = config.get(configName, "type");
    if (!configType) {
      return res
        .status(400)
        .json({ success: false, error: "config not found" });
    }
    //check if configName exist in runningprocess.txt
    let runningProcess = fs.readFileSync("runningprocess.txt", "utf8");
    let runningProcessArray = runningProcess.split("\n");
    let runningProcessIndex = runningProcessArray.findIndex((line) =>
      line.includes(`${configName}|`)
    );
    //if exist, return success : false message already running
    if (runningProcessIndex != -1) {
      let runningTime = runningProcessArray[runningProcessIndex].split("|")[1];
      //if runningTime is more than 5 minutes, remove it from runningprocess.txt
      if (Date.now() - runningTime > 60000) {
        runningProcessArray.splice(runningProcessIndex, 1);
        fs.writeFileSync("runningprocess.txt", runningProcessArray.join("\n"));
      } else {
        return res
          .status(200)
          .json({ success: false, message: "already running" });
      }
    }
    //if not exist, add configName|timestamp to runningprocess.txt
    runningProcessArray.push(`${configName}|${Date.now()}`);
    fs.writeFileSync("runningprocess.txt", runningProcessArray.join("\n"));

    //stop service sslocal_$configName
    exec(`systemctl stop sslocal_${configName}`, (err, stdout, stderr) => {
      if (err) {
        console.error(`Error stopping service: ${err}`);
        return;
      }
    });

    let result;
    let serverConfig;
    if (configType == "tencent") {
      serverConfig = configs.tencent.find(
        (config) => config.configName == configName
      );
      result = await newIpTencent(serverConfig);
    } else if (configType == "azure") {
      serverConfig = configs.azure.find(
        (config) => config.configName == configName
      );
      result = await newIpAzure(serverConfig);
    } else if (configType == "aws") {
      serverConfig = configs.aws.find(
        (config) => config.configName == configName
      );
      result = await newIpAws(serverConfig);
    }
    const socks5Port = serverConfig.socks5Port;
    const httpPort = serverConfig.httpPort;
    const publicIp = result.newIp;
    //check if host exist on /etc/hosts, if yes delete the line cotaint host
    const hosts = fs.readFileSync("/etc/hosts", "utf8");
    const hostsArray = hosts.split("\n");
    const hostIndex = hostsArray.findIndex((line) => line.includes(host));
    if (hostIndex != -1) {
      hostsArray.splice(hostIndex, 1);
      const newHosts = hostsArray.join("\n");
      fs.writeFileSync("/etc/hosts", newHosts);
    }
    //add host to /etc/hosts
    fs.appendFileSync("/etc/hosts", `${publicIp} ${host}\n`);
    //update cloudflare dns record
    console.log(
      `profile: ${configName}, old ip: ${result.oldIp}, new ip: ${result.newIp}`
    );
    const cf = require("cloudflare")({
      email: email,
      key: token,
    });
    const zoneId = await cf.zones.browse().then((data) => {
      const zone = data.result.find((zone) => zone.name == domain);
      return zone.id;
    });
    //check if dns record for host exist, if not create one, if yes update it
    const dnsRecord = await cf.dnsRecords.browse(zoneId).then((data) => {
      const record = data.result.find((record) => record.name == host);
      return record;
    });
    if (dnsRecord == undefined) {
      await cf.dnsRecords.add(zoneId, {
        type: "A",
        name: host,
        content: publicIp,
        ttl: 1,
        proxied: false,
      });
    } else {
      await cf.dnsRecords.edit(zoneId, dnsRecord.id, {
        type: "A",
        name: host,
        content: publicIp,
        ttl: 1,
        proxied: false,
      });
    }

    const configPath = `/etc/shadowsocks/config_${configName}.json`;
    const configTemplate = fs.readFileSync("configtemplate.json", "utf8");
    const configTemplateJson = JSON.parse(configTemplate);
    configTemplateJson.server = host;
    configTemplateJson.server_port = 8388;
    configTemplateJson.password = "Pass";
    configTemplateJson.method = "aes-128-gcm";
    configTemplateJson.mode = "tcp_and_udp";
    configTemplateJson.local_address = local_ip;
    configTemplateJson.local_port = parseInt(socks5Port);
    configTemplateJson.locals[0].local_address = local_ip;
    configTemplateJson.locals[0].local_port = parseInt(httpPort);
    fs.writeFileSync(configPath, JSON.stringify(configTemplateJson));

    const servicePath = `/etc/systemd/system/sslocal_${configName}.service`;
    const serviceTemplate = fs.readFileSync("service_template.service", "utf8");

    const serviceTemplateArray = serviceTemplate.split("\n");
    const serviceTemplateIndex = serviceTemplateArray.findIndex((line) =>
      line.includes("ExecStart")
    );
    serviceTemplateArray[
      serviceTemplateIndex
    ] = `ExecStart=/usr/local/bin/sslocal -c /etc/shadowsocks/config_${configName}.json`;
    const newServiceTemplate = serviceTemplateArray.join("\n");
    fs.writeFileSync(servicePath, newServiceTemplate);
    //enable and start sslocal_$configName.service
    await exec(`systemctl daemon-reload`);
    await exec(`systemctl start sslocal_${configName}.service`);
    let retry = 0;
    let maxRetry = 10;
    while (true) {
      try {
        //check socks5://localhost:socks5Port to fake.chiacloud.farm/ip using axios, if response.data == publicIp, break
        const socks5Url = `socks5://localhost:${socks5Port}`;
        const agent = new SocksProxyAgent(socks5Url);

        const response = await axios.request({
          url: "http://fake.chiacloud.farm/ip",
          method: "GET",
          httpsAgent: agent,
          httpAgent: agent,
          timeout: 1000,
        });
        if (response.data == publicIp) {
          break;
        }
        if (retry >= maxRetry) {
          throw new Error("retry proxy connection exceed maxRetry");
        }
      } catch (err) {
        await sleep(500);
        retry++;
        continue;
      }
    }
    //remove configName from runningprocess.txt
    runningProcess = fs.readFileSync("runningprocess.txt", "utf8");
    runningProcessArray = runningProcess.split("\n");
    runningProcessIndex = runningProcessArray.findIndex((line) =>
      line.includes(`${configName}|`)
    );
    runningProcessArray.splice(runningProcessIndex, 1);
    const newRunningProcess = runningProcessArray.join("\n");
    fs.writeFileSync("runningprocess.txt", newRunningProcess);

    return res.status(200).json({ success: true, result });
  } catch (err) {
    console.error(err);
    //remove configName from runningprocess.txt
    runningProcess = fs.readFileSync("runningprocess.txt", "utf8");
    runningProcessArray = runningProcess.split("\n");
    runningProcessIndex = runningProcessArray.findIndex(
      (line) => line == configName
    );
    runningProcessArray.splice(runningProcessIndex, 1);
    const newRunningProcess = runningProcessArray.join("\n");
    fs.writeFileSync("runningprocess.txt", newRunningProcess);
    return res.status(500).json({ success: false, error: err.message });
  }
});
