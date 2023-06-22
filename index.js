const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const fs = require('fs')
const morgan = require('morgan')
const axios = require('axios')
const { spawn } = require('child_process')
const { performance } = require('perf_hooks')
const { SocksProxyAgent } = require('socks-proxy-agent')
const tencentcloud = require('tencentcloud-sdk-nodejs')
const { DefaultAzureCredential } = require('@azure/identity')
const { NetworkManagementClient } = require('@azure/arm-network')
const {
  EC2Client,
  AllocateAddressCommand,
  DisassociateAddressCommand,
  AssociateAddressCommand,
  DescribeAddressesCommand,
  ReleaseAddressCommand,
  DescribeInstancesCommand,
} = require('@aws-sdk/client-ec2')
const ConfigParser = require('configparser')
const { exec } = require('child_process')
app.use(bodyParser.json())
app.use(morgan('combined'))
const config = new ConfigParser()
config.read('config.conf')
const prefix = config.get('api', 'prefix')
const appPort = config.get('api', 'port')
const civoRouter = require('./routers/civo')
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
//clearup runningprocess.txt file
fs.writeFile('runningprocess.txt', '', function (err) {
  if (err) throw err
})

function startSessionLoop() {
  sessionLoop = spawn('node', ['loop.js'])
  sessionLoop.on('error', (error) => {
    console.error(`Session loop error: ${error.message}`)
  })
  sessionLoop.stdout.pipe(process.stdout)
  sessionLoop.on('exit', (code, signal) => {
    //console.log(`Session loop exited with code ${code} and signal ${signal}`);
    if (code !== 0 || code === 0) {
      //console.log("Respawning session loop...");
      startSessionLoop()
    }
  })
}
app.use(`/${prefix}/civo`, civoRouter)
if (require.main === module) {
  startSessionLoop()
  app.listen(appPort, '0.0.0.0', () => {
    console.log(`Listening on port ${appPort}`)
  })
}
async function newIpAws(serverConfig) {
  const accessKey = serverConfig.accessKey
  const secretKey = serverConfig.secretKey
  const instanceId = serverConfig.instanceId
  const region = serverConfig.region
  const ec2 = new EC2Client({
    region: region,
    credentials: {
      accessKeyId: accessKey,
      secretAccessKey: secretKey,
    },
  })
  async function disassociateAndRelease() {
    //list all elastic ip with tag instance=instanceId
    try {
      const command = new DescribeAddressesCommand({
        Filters: [
          {
            Name: 'tag:instance',
            Values: [instanceId],
          },
        ],
      })
      const response = await ec2.send(command)
      if (response.Addresses.length > 0) {
        console.log(response)
        for (let i = 0; i < response.Addresses.length; i++) {
          try {
            const command = new DisassociateAddressCommand({
              AssociationId: response.Addresses[i].AssociationId,
            })
            await ec2.send(command)
          } catch (err) {}
          try {
            const command2 = new ReleaseAddressCommand({
              AllocationId: response.Addresses[i].AllocationId,
            })
            await ec2.send(command2)
          } catch (err) {}
        }
      }
    } catch (err) {
      console.error(err)
    }
  }

  async function getInstanceIp() {
    try {
      const command = new DescribeInstancesCommand({
        InstanceIds: [instanceId],
      })
      const response = await ec2.send(command)
      return response.Reservations[0].Instances[0].PublicIpAddress
    } catch (err) {
      console.error(err)
    }
  }
  const oldIp = await getInstanceIp()
  async function allocateElasticIp() {
    try {
      const command = new AllocateAddressCommand({
        TagSpecifications: [
          {
            ResourceType: 'elastic-ip',
            Tags: [{ Key: 'instance', Value: instanceId }],
          },
        ],
      })
      const response = await ec2.send(command)
      return {
        elasticIp: response.PublicIp,
        allocationId: response.AllocationId,
      }
    } catch (err) {
      console.error(err)
    }
  }
  await disassociateAndRelease()
  const allocateIp = await allocateElasticIp()
  async function associateIp() {
    try {
      const command = new AssociateAddressCommand({
        InstanceId: instanceId,
        PublicIp: allocateIp.elasticIp,
      })
      const response = await ec2.send(command)
      return response
    } catch (err) {
      console.error(err)
    }
  }
  const asassociate = await associateIp()
  await new Promise((resolve) => setTimeout(resolve, 1500))
  async function disassociateIp() {
    try {
      const command = new DisassociateAddressCommand({
        PublicIp: allocateIp.elasticIp,
      })
      const response = await ec2.send(command)
      return response
    } catch (err) {
      console.error(err)
    }
  }
  disassociateIp()
  async function releaseIp() {
    try {
      const command = new ReleaseAddressCommand({
        AllocationId: allocateIp.allocationId,
      })
      const response = await ec2.send(command)
      return response
    } catch (err) {
      console.error(err)
    }
  }
  releaseIp()
  await new Promise((resolve) => setTimeout(resolve, 1500))
  const newIp = await getInstanceIp()
  return { oldIp: oldIp, newIp: newIp }
}

async function newIpAzure(serverConfig) {
  process.env.AZURE_CLIENT_ID = serverConfig.clientId
  process.env.AZURE_CLIENT_SECRET = serverConfig.clientSecret
  process.env.AZURE_SUBSCRIPTION_ID = serverConfig.subscriptionId
  process.env.AZURE_TENANT_ID = serverConfig.tenantId
  const AZURE_CLIENT_ID = process.env.AZURE_CLIENT_ID
  const AZURE_CLIENT_SECRET = process.env.AZURE_CLIENT_SECRET
  const AZURE_SUBSCRIPTION_ID = process.env.AZURE_SUBSCRIPTION_ID
  const AZURE_TENANT_ID = process.env.AZURE_TENANT_ID
  const resourceGroupName = serverConfig.resourceGroupName
  const publicIpName = serverConfig.publicIpName
  const nicName = serverConfig.nicName

  const credential = new DefaultAzureCredential({
    clientId: AZURE_CLIENT_ID,
    clientSecret: AZURE_CLIENT_SECRET,
    tenantId: AZURE_TENANT_ID,
  })

  const networkClient = new NetworkManagementClient(
    credential,
    AZURE_SUBSCRIPTION_ID
  )

  async function getNic() {
    const nic = await networkClient.networkInterfaces.get(
      resourceGroupName,
      nicName
    )
    return nic
  }

  async function getIpDetail() {
    const ip = await networkClient.publicIPAddresses.get(
      resourceGroupName,
      publicIpName
    )
    return ip
  }

  async function disassociate(nic) {
    nic.ipConfigurations[0].publicIPAddress = null
    const disassociate =
      await networkClient.networkInterfaces.beginCreateOrUpdate(
        resourceGroupName,
        nicName,
        nic
      )
    return disassociate
  }

  async function associate(nic, ip) {
    nic.ipConfigurations[0].publicIPAddress = ip

    await networkClient.networkInterfaces.beginCreateOrUpdate(
      resourceGroupName,
      nicName,
      nic
    )
  }
  let oldIp
  let ip, nic
  let retries = 0
  let max = 10
  while (true) {
    try {
      ;[ip, nic] = await Promise.all([getIpDetail(), getNic()])
      break
    } catch (err) {
      retries++
      if (retries < max) {
        continue
      } else if (retries === max) {
        throw new Error('Failed to get ip or nic on first action')
      }
    }
  }

  await sleep(500)
  oldIp = ip.ipAddress
  if (!oldIp) {
    oldIp = null
  }
  await disassociate(nic)
  await sleep(500)
  nic = await getNic()
  retries = 0
  max = 10
  while (true) {
    if (!nic.ipConfigurations[0].publicIPAddress) {
      try {
        await disassociate(nic)
      } catch (err) {}
      break
    } else {
      try {
        await disassociate(nic)
        nic = await getNic()
        await sleep(500)
        retries++
        if (retries < max) {
          continue
        } else if (retries === max) {
          throw new Error('Failed to disassociate ip')
        }
      } catch (err) {}
    }
  }
  retries = 0
  max = 10
  while (true) {
    try {
      ;[ip, nic] = await Promise.all([getIpDetail(), getNic()])
      break
    } catch (err) {
      retries++
      if (retries < max) {
        continue
      } else if (retries === max) {
        throw new Error('Failed to get ip or nic on seconds action')
      }
    }
  }
  await sleep(500)
  retries = 0
  max = 10
  while (true) {
    try {
      await associate(nic, ip)
      await sleep(500)
      break
    } catch (err) {
      retries++
      if (retries < max) {
        continue
      } else if (retries === max) {
        throw new Error('Failed to associate ip')
      }
    }
  }
  retries = 0
  max = 10
  while (true) {
    try {
      ;[ip, nic] = await Promise.all([getIpDetail(), getNic()])
      break
    } catch (err) {
      retries++
      if (retries < max) {
        continue
      } else if (retries === max) {
        throw new Error('Failed to get ip or nic on third action')
      }
    }
  }
  retries = 0
  max = 50
  let newIp = ip.ipAddress
  while (true) {
    if (!newIp || newIp === oldIp) {
      await sleep(1000)
      ip = await getIpDetail()
      newIp = ip.ipAddress
      retries++
      if (retries < max) {
        continue
      } else {
        throw new Error('Failed to get new I, max retries reached')
      }
    } else {
      break
    }
  }

  if (!newIp) {
    throw new Error('Failed to get new IP')
  }
  return { oldIp: oldIp, newIp: newIp }
}

async function newIpTencent(serverConfig) {
  const CvmClient = tencentcloud.cvm.v20170312.Client
  const secretId = serverConfig.secretId
  const secretKey = serverConfig.secretKey
  const region = serverConfig.region
  const instanceId = serverConfig.instanceId
  const clientConfig = {
    credential: {
      secretId: secretId,
      secretKey: secretKey,
    },
    region: region,
    profile: {
      httpProfile: {
        endpoint: 'cvm.tencentcloudapi.com',
      },
    },
  }
  const client = new CvmClient(clientConfig)
  const params = {
    InstanceIds: [instanceId],
  }
  const stopParams = {
    InstanceIds: [`${instanceId}`],
    StopType: 'HARD',
    StoppedMode: 'STOP_CHARGING',
  }
  let instanceDescribed = await client.DescribeInstances(params)
  let oldIp = ''
  if (
    instanceDescribed.InstanceSet[0].PublicIpAddresses == null ||
    instanceDescribed.InstanceSet[0].PublicIpAddresses.length === 0
  ) {
    oldIp = ''
  } else {
    oldIp = instanceDescribed.InstanceSet[0].PublicIpAddresses[0]
  }
  instanceDescribed = await client.DescribeInstances(params)
  if (instanceDescribed.InstanceSet[0].InstanceState === 'RUNNING') {
    const stopData = await client.StopInstances(stopParams).then(async () => {
      await new Promise((resolve) => setTimeout(resolve, 2000))
      instanceDescribed = await client.DescribeInstances(params)
      while (true) {
        if (
          instanceDescribed.InstanceSet[0].InstanceState == 'STARTING' ||
          instanceDescribed.InstanceSet[0].InstanceState == 'STOPPING'
        ) {
          await new Promise((resolve) => setTimeout(resolve, 2000))
          instanceDescribed = await client.DescribeInstances(params)
        } else {
          break
        }
      }
      await client.StartInstances(params)
      while (true) {
        if (instanceDescribed.InstanceSet[0].InstanceState == 'RUNNING') {
          publicIp = instanceDescribed.InstanceSet[0].PublicIpAddresses[0]
          break
        } else {
          instanceDescribed = await client.DescribeInstances(params)
        }
      }
    })
  } else if (instanceDescribed.InstanceSet[0].InstanceState === 'STOPPED') {
    await client.StartInstances(params)
    while (true) {
      if (instanceDescribed.InstanceSet[0].InstanceState == 'RUNNING') {
        publicIp = instanceDescribed.InstanceSet[0].PublicIpAddresses[0]
        break
      } else {
        instanceDescribed = await client.DescribeInstances(params)
      }
    }
  }
  return { oldIp: oldIp, newIp: publicIp }
}

async function parseConfig() {
  config.read('config.conf')
  const confList = config.sections()
  let tencentConfigList = []
  let civoConfigList = []
  let azureConfigList = []
  let awsConfigList = []
  let biznetConfigList = []
  let cloudflareConfig = {}
  let apiConfig = {}
  for (let i = 0; i < confList.length; i++) {
    const configName = confList[i]
    const configType = config.get(confList[i], 'type')
    if (configType == 'tencent') {
      const secretId = config.get(confList[i], 'secretId')
      const secretKey = config.get(confList[i], 'secretKey')
      const region = config.get(confList[i], 'region')
      const instanceId = config.get(confList[i], 'instanceId')
      const socks5Port = config.get(confList[i], 'socks5Port')
      const httpPort = config.get(confList[i], 'httpPort')
      const socks5User = config.get(confList[i], 'socks5User')
      const socks5Pass = config.get(confList[i], 'socks5Pass')

      const configration = {
        configName: configName,
        secretId: secretId,
        secretKey: secretKey,
        region: region,
        instanceId: instanceId,
        socks5Port: socks5Port,
        httpPort: httpPort,
      }
      if (socks5User && socks5Pass) {
        configration.socks5User = socks5User
        configration.socks5Pass = socks5Pass
      }
      tencentConfigList.push(configration)
    } else if (configType == 'cloudflare') {
      const email = config.get(confList[i], 'email')
      const token = config.get(confList[i], 'token')
      const domain = config.get(confList[i], 'domain')
      let zoneId = config.get(confList[i], 'zoneId')
      const configName = confList[i]
      cloudflareConfig.email = email
      cloudflareConfig.token = token
      cloudflareConfig.domain = domain
      cloudflareConfig.configName = configName
      if (zoneId) {
        cloudflareConfig.zoneId = zoneId
      }
    } else if (configType == 'api') {
      const prefix = config.get(confList[i], 'prefix')
      const port = config.get(confList[i], 'port')
      const hostLocalIp = config.get(confList[i], 'hostLocalIp')
      const hostPublicIp = config.get(confList[i], 'hostPublicIp')
      const key = config.get(confList[i], 'key')
      const apiHostName = config.get(confList[i], 'apiHostName')
      apiConfig.prefix = prefix
      apiConfig.port = port
      apiConfig.hostLocalIp = hostLocalIp
      apiConfig.hostPublicIp = hostPublicIp
      apiConfig.key = key
      apiConfig.apiHostName = apiHostName
    } else if (configType == 'azure') {
      const socks5Port = config.get(confList[i], 'socks5Port')
      const httpPort = config.get(confList[i], 'httpPort')
      const clientId = config.get(confList[i], 'clientId')
      const clientSecret = config.get(confList[i], 'clientSecret')
      const tenantId = config.get(confList[i], 'tenantId')
      const subscriptionId = config.get(confList[i], 'subscriptionId')
      const resourceGroupName = config.get(confList[i], 'resourceGroupName')
      const publicIpName = config.get(confList[i], 'publicIpName')
      const ipConfigName = config.get(confList[i], 'ipConfigName')
      const nicName = config.get(confList[i], 'nicName')
      const vmName = config.get(confList[i], 'vmName')
      const socks5User = config.get(confList[i], 'socks5User')
      const socks5Pass = config.get(confList[i], 'socks5Pass')
      const configuration = {
        configName: confList[i],
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
      }
      if (socks5User && socks5Pass) {
        configuration.socks5User = socks5User
        configuration.socks5Pass = socks5Pass
      }
      azureConfigList.push(configuration)
    } else if (configType == 'aws') {
      const accessKey = config.get(confList[i], 'accessKey')
      const secretKey = config.get(confList[i], 'secretKey')
      const instanceId = config.get(confList[i], 'instanceId')
      const region = config.get(confList[i], 'region')
      const socks5Port = config.get(confList[i], 'socks5Port')
      const httpPort = config.get(confList[i], 'httpPort')
      const socks5User = config.get(confList[i], 'socks5User')
      const socks5Pass = config.get(confList[i], 'socks5Pass')
      const configuration = {
        configName: confList[i],
        accessKey: accessKey,
        secretKey: secretKey,
        instanceId: instanceId,
        region: region,
        socks5Port: socks5Port,
        httpPort: httpPort,
      }
      if (socks5User && socks5Pass) {
        configuration.socks5User = socks5User
        configuration.socks5Pass = socks5Pass
      }
      awsConfigList.push(configuration)
    } else if (configType == 'civo') {
      const token = config.get(confList[i], 'token')
      const cookie = config.get(confList[i], 'cookie')
      const instanceId = config.get(confList[i], 'instanceId')
      const socks5Port = config.get(confList[i], 'socks5Port')
      const httpPort = config.get(confList[i], 'httpPort')
      const socks5User = config.get(confList[i], 'socks5User')
      const socks5Pass = config.get(confList[i], 'socks5Pass')
      const region = config.get(confList[i], 'region')
      const configuration = {
        configName: confList[i],
        token: token,
        cookie: cookie,
        region: region,
        instanceId: instanceId,
        socks5Port: socks5Port,
        httpPort: httpPort,
      }
      if (socks5User && socks5Pass) {
        configuration.socks5User = socks5User
        configuration.socks5Pass = socks5Pass
      }
      civoConfigList.push(configuration)
    } else if (configType == 'biznet') {
      const token = config.get(confList[i], 'token')
      const projectId = config.get(confList[i], 'projectId')
      const networkId = config.get(confList[i], 'networkId')
      const portId = config.get(confList[i], 'portId')
      const region = config.get(confList[i], 'region')
      const socks5Port = config.get(confList[i], 'socks5Port')
      const httpPort = config.get(confList[i], 'httpPort')
      const configuration = {
        configName: confList[i],
        token: token,
        projectId: projectId,
        networkId: networkId,
        portId: portId,
        region: region,
        socks5Port: socks5Port,
        httpPort: httpPort,
      }
      if (socks5User && socks5Pass) {
        configuration.socks5User = socks5User
        configuration.socks5Pass = socks5Pass
      }
      biznetConfigList.push(configuration)
    }
  }
  return {
    configs: {
      api: apiConfig,
      cloudflare: cloudflareConfig,
      civo: civoConfigList,
      tencent: tencentConfigList,
      azure: azureConfigList,
      aws: awsConfigList,
    },
  }
}

async function checkCivo(serverConfig) {
  const cookie = serverConfig.cookie
  const instanceId = serverConfig.instanceId
  const token = serverConfig.token
  const configName = serverConfig.configName
  async function getPublicIp(configName, cookie, instanceId) {
    const url = `https://dashboard.civo.com/instances/${instanceId}`
    const axiosConfig = {
      headers: {
        authority: 'dashboard.civo.com',
        accept:
          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'max-age=0',
        cookie: `_civo_session=${cookie};`,
        referer: 'https://dashboard.civo.com/instances',
        'sec-ch-ua':
          '"Google Chrome";v="113", "Chromium";v="113", "Not-A.Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Linux"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent':
          'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
      },
    }
    const result = {}
    try {
      const response = await axios.get(url, axiosConfig)
      const body = response.data
      let ip
      // if body contain <meta property="og:title" content="Log in to your dashboard - Civo.com" /> return false
      if (
        body.match(
          /<meta property="og:title" content="Log in to your dashboard - Civo.com" \/>/
        )
      ) {
        result.success = false
        result.message = 'Invalid cookie'
        return result
      }
      //parse ipaddress from this pattern <li>Public IP: <span class="js-clipboard" data-clipboard-text="74.220.18.67">74.220.18.67</span>
      try {
        ip = body.match(
          /<li>Public IP: <span class="js-clipboard" data-clipboard-text="(.*)">(.*)<\/span>/
        )[1]
      } catch (e) {
        ip = null
      }

      if (ip) {
        result.success = true
        result.configName = configName
        result.ip = ip
      }
    } catch (error) {
      console.log(error)
      result.status = false
    }
    return result
  }
  const result = await getPublicIp(configName, cookie, instanceId)
  return result
}

async function checkCloudflare(serverConfig) {
  const cloudflareEmail = serverConfig.email
  const cloudflareKey = serverConfig.token
  const cloudflareDomain = serverConfig.domain
  const configName = serverConfig.configName
  let zoneId = serverConfig.zoneId
  let result = {}
  result.configName = configName
  try {
    const cf = require('cloudflare')({
      email: cloudflareEmail,
      key: cloudflareKey,
    })
    if (!zoneId) {
      console.log('zoneId not found, try to get zoneId from cloudflare')
      zoneId = await cf.zones.browse().then((data) => {
        const zone = data.result.find((zone) => zone.name == cloudflareDomain)
        return zone.id
      })
      if (!zoneId) {
        return false
      }
    }

    result.zoneId = zoneId
    result.success = true
  } catch (err) {
    result.success = false
  }
  return result
}

async function checkTencent(serverConfig) {
  const CvmClient = tencentcloud.cvm.v20170312.Client
  const secretId = serverConfig.secretId
  const secretKey = serverConfig.secretKey
  const region = serverConfig.region
  const instanceId = serverConfig.instanceId
  const configName = serverConfig.configName
  const clientConfig = {
    credential: {
      secretId: secretId,
      secretKey: secretKey,
    },
    region: region,
    profile: {
      httpProfile: {
        endpoint: 'cvm.tencentcloudapi.com',
      },
    },
  }
  const client = new CvmClient(clientConfig)
  const params = {
    InstanceIds: [instanceId],
  }
  let result = {}
  result.configName = serverConfig.configName
  try {
    let instanceDescribed = await client.DescribeInstances(params)
    let oldIp = ''
    if (
      instanceDescribed.InstanceSet[0].PublicIpAddresses == null ||
      instanceDescribed.InstanceSet[0].PublicIpAddresses.length === 0
    ) {
      oldIp = ''
    } else {
      oldIp = instanceDescribed.InstanceSet[0].PublicIpAddresses[0]
    }
    result.success = true
    result.ip = oldIp
  } catch (err) {
    result.success = false
  }
  return result
}
async function checkAws(serverConfig) {
  const accessKey = serverConfig.accessKey
  const secretKey = serverConfig.secretKey
  const instanceId = serverConfig.instanceId
  const region = serverConfig.region
  const configName = serverConfig.configName
  const ec2 = new EC2Client({
    region: region,
    credentials: {
      accessKeyId: accessKey,
      secretAccessKey: secretKey,
    },
  })
  let result = {}
  result.configName = configName
  try {
    async function getInstanceIp() {
      try {
        const command = new DescribeInstancesCommand({
          InstanceIds: [instanceId],
        })
        const response = await ec2.send(command)
        return response.Reservations[0].Instances[0].PublicIpAddress
      } catch (err) {
        console.error(err)
      }
    }
    const oldIp = await getInstanceIp()
    result.success = true
    result.ip = oldIp
  } catch (err) {
    result.success = false
  }
  return result
}
async function checkAzure(serverConfig) {
  process.env.AZURE_CLIENT_ID = serverConfig.clientId
  process.env.AZURE_CLIENT_SECRET = serverConfig.clientSecret
  process.env.AZURE_SUBSCRIPTION_ID = serverConfig.subscriptionId
  process.env.AZURE_TENANT_ID = serverConfig.tenantId
  const AZURE_CLIENT_ID = process.env.AZURE_CLIENT_ID
  const AZURE_CLIENT_SECRET = process.env.AZURE_CLIENT_SECRET
  const AZURE_SUBSCRIPTION_ID = process.env.AZURE_SUBSCRIPTION_ID
  const AZURE_TENANT_ID = process.env.AZURE_TENANT_ID
  const resourceGroupName = serverConfig.resourceGroupName
  const publicIpName = serverConfig.publicIpName
  const nicName = serverConfig.nicName

  const credential = new DefaultAzureCredential({
    clientId: AZURE_CLIENT_ID,
    clientSecret: AZURE_CLIENT_SECRET,
    tenantId: AZURE_TENANT_ID,
  })
  let result = {}
  result.configName = serverConfig.configName
  try {
    const networkClient = new NetworkManagementClient(
      credential,
      AZURE_SUBSCRIPTION_ID
    )
    async function getIpDetail() {
      const ip = await networkClient.publicIPAddresses.get(
        resourceGroupName,
        publicIpName
      )
      return ip
    }
    async function getNic() {
      const nic = await networkClient.networkInterfaces.get(
        resourceGroupName,
        nicName
      )
      return nic
    }
    const [nic, ip] = await Promise.all([getNic(), getIpDetail()])
    if (nic && ip) {
      result.success = true
      if (ip.ipAddress) {
        result.ip = ip.ipAddress
      }
    }
  } catch (error) {
    result.success = false
    result.error = error.message
  }
  return result
}

async function refreshCreds(response, configName) {
  const body = response.data
  const token = body.match(/<meta name="csrf-token" content="(.*)" \/>/)[1]
  const cookie = response.headers['set-cookie'][0].split(';')[0].split('=')[1]
  const lastCheck = new Date().toISOString()
  config.set(configName, 'cookie', cookie)
  config.set(configName, 'token', token)
  config.set(configName, 'lastCheck', lastCheck)
  config.write('config.conf')
}

app.get(`/${prefix}/newip/`, async (req, res) => {
  const startTime = performance.now()
  let configName = req.query.configName
  let port = req.query.port
  const { configs } = await parseConfig()
  //only accept one of query
  if (!configName && !port) {
    return res
      .status(400)
      .json({ success: false, error: 'bad request, no query found' })
  }
  if (configName && port) {
    return res.status(400).json({
      success: false,
      error: 'bad request, only accept one query (configName/port)',
    })
  }

  if (!configName) {
    try {
      const tencentConfig = configs.tencent.find(
        (config) => config.socks5Port == port || config.httpPort == port
      )
      const azureConfig = configs.azure.find(
        (config) => config.socks5Port == port || config.httpPort == port
      )
      const awsConfig = configs.aws.find(
        (config) => config.socks5Port == port || config.httpPort == port
      )

      const foundConfig = tencentConfig || azureConfig || awsConfig

      if (!foundConfig) {
        return res.status(400).json({
          success: false,
          error: `bad request, no config found with port ${port}`,
        })
      }

      configName = foundConfig.configName
    } catch (err) {
      console.error(err)
      return res.status(500).json({ success: false, error: err.message })
    }
  }
  console.log(`hit newip ${configName}`)
  let result = {}
  try {
    const apiConfig = configs.api
    const apiHostName = apiConfig.apiHostName
    const cloudflareConfig = configs.cloudflare
    let zoneId = cloudflareConfig.zoneId
    const domain = cloudflareConfig.domain
    const email = cloudflareConfig.email
    const token = cloudflareConfig.token
    const hostLocalIp = apiConfig.hostLocalIp
    const hostPublicIp = apiConfig.hostPublicIp
    const host = `${configName}.${domain}`
    const configType = config.get(configName, 'type')
    if (!configType) {
      return res.status(400).json({ success: false, error: 'config not found' })
    }
    //check if configName exist in runningprocess.txt
    let runningProcess = fs.readFileSync('runningprocess.txt', 'utf8')
    let runningProcessArray = runningProcess.split('\n')
    let runningProcessIndex = runningProcessArray.findIndex((line) =>
      line.includes(`${configName}|`)
    )
    //if exist, return success : false message already running
    if (runningProcessIndex != -1) {
      let runningTime = runningProcessArray[runningProcessIndex].split('|')[1]
      //if runningTime is more than 5 minutes, remove it from runningprocess.txt
      if (Date.now() - runningTime > 60000) {
        runningProcessArray.splice(runningProcessIndex, 1)
        fs.writeFileSync('runningprocess.txt', runningProcessArray.join('\n'))
      } else {
        return res
          .status(200)
          .json({ success: false, message: 'already running' })
      }
    }
    //if not exist, add configName|timestamp to runningprocess.txt
    runningProcessArray.push(`${configName}|${Date.now()}`)
    fs.writeFileSync('runningprocess.txt', runningProcessArray.join('\n'))

    //stop service sslocal_$configName
    exec(`systemctl stop sslocal_${configName}`, (err, stdout, stderr) => {
      if (err) {
        console.error(`Error stopping service: ${err}`)
        return
      }
    })
    let serverConfig
    if (configType == 'tencent') {
      serverConfig = configs.tencent.find(
        (config) => config.configName == configName
      )
      result = await newIpTencent(serverConfig)
    } else if (configType == 'azure') {
      serverConfig = configs.azure.find(
        (config) => config.configName == configName
      )
      result = await newIpAzure(serverConfig)
    } else if (configType == 'aws') {
      serverConfig = configs.aws.find(
        (config) => config.configName == configName
      )
      result = await newIpAws(serverConfig)
    }
    const socks5Port = serverConfig.socks5Port
    const httpPort = serverConfig.httpPort
    const publicIp = result.newIp
    const socks5User = serverConfig.socks5User
    const socks5Pass = serverConfig.socks5Pass
    if (socks5User && socks5Pass) {
      //generate auth_${configName}.json on /etc/shadowsocks
      const auth = {
        password: {
          users: [
            {
              user_name: socks5User,
              password: socks5Pass,
            },
          ],
        },
      }
      fs.writeFileSync(
        `/etc/shadowsocks/auth_${configName}.json`,
        JSON.stringify(auth)
      )
    }
    //check if host exist on /etc/hosts, if yes delete the line cotaint host
    const hosts = fs.readFileSync('/etc/hosts', 'utf8')
    const hostsArray = hosts.split('\n')
    const hostIndex = hostsArray.findIndex((line) => line.includes(host))
    if (hostIndex != -1) {
      hostsArray.splice(hostIndex, 1)
      const newHosts = hostsArray.join('\n')
      fs.writeFileSync('/etc/hosts', newHosts)
    }
    //add host to /etc/hosts
    fs.appendFileSync('/etc/hosts', `${publicIp} ${host}\n`)
    //update cloudflare dns record
    console.log(
      `profile: ${configName}, old ip: ${result.oldIp}, new ip: ${result.newIp}`
    )
    const cf = require('cloudflare')({
      email: email,
      key: token,
    })
    if (!zoneId) {
      zoneId = await cf.zones.browse().then((data) => {
        const zone = data.result.find((zone) => zone.name == domain)
        return zone.id
      })
      if (!zoneId) {
        return res.status(400).json({
          success: false,
          error: `bad request, no zone found with domain ${domain}`,
        })
      }
    }
    //check if dns record for host exist, if not create one, if yes update it
    const dnsRecord = await cf.dnsRecords.browse(zoneId).then((data) => {
      const record = data.result.find((record) => record.name == host)
      return record
    })
    if (dnsRecord == undefined) {
      await cf.dnsRecords.add(zoneId, {
        type: 'A',
        name: host,
        content: publicIp,
        ttl: 1,
        proxied: false,
      })
    } else {
      await cf.dnsRecords.edit(zoneId, dnsRecord.id, {
        type: 'A',
        name: host,
        content: publicIp,
        ttl: 1,
        proxied: false,
      })
    }
    const apiHostNameRecord = await cf.dnsRecords
      .browse(zoneId)
      .then((data) => {
        const record = data.result.find((record) => record.name == apiHostName)
        return record
      })
    if (apiHostNameRecord == undefined) {
      await cf.dnsRecords.add(zoneId, {
        type: 'A',
        name: apiHostName,
        content: hostPublicIp,
        ttl: 1,
        proxied: false,
      })
    } else if (apiHostNameRecord.content != hostPublicIp) {
      await cf.dnsRecords.edit(zoneId, apiHostNameRecord.id, {
        type: 'A',
        name: apiHostName,
        content: hostPublicIp,
        ttl: 1,
        proxied: false,
      })
    }

    const configPath = `/etc/shadowsocks/config_${configName}.json`
    const configTemplate = fs.readFileSync('configtemplate.json', 'utf8')
    const configTemplateJson = JSON.parse(configTemplate)
    configTemplateJson.server = host
    configTemplateJson.server_port = 8388
    configTemplateJson.password = 'Pass'
    configTemplateJson.method = 'aes-128-gcm'
    configTemplateJson.mode = 'tcp_and_udp'
    configTemplateJson.locals[0].local_address = hostLocalIp
    configTemplateJson.locals[0].local_port = parseInt(socks5Port)
    configTemplateJson.locals[0].protocol = 'socks'

    if (socks5User && socks5Pass) {
      configTemplateJson.locals[0].socks5_auth_config_path = `/etc/shadowsocks/auth_${configName}.json`
    }
    configTemplateJson.locals[1].protocol = 'http'
    configTemplateJson.locals[1].local_address = hostLocalIp
    configTemplateJson.locals[1].local_port = parseInt(httpPort)
    //check if directory /etc/shadowsocks/ exist, if not create one
    if (!fs.existsSync('/etc/shadowsocks')) {
      fs.mkdirSync('/etc/shadowsocks')
    }
    if (!fs.existsSync(configPath)) {
      try {
        fs.writeFileSync(configPath, '')
        console.log(`Config file ${configPath} created successfully.`)
      } catch (err) {
        console.error(`Error creating config file: ${err}`)
      }
    } else {
      fs.writeFileSync(configPath, JSON.stringify(configTemplateJson))
      console.log(`Config file ${configPath} updated successfully.`)
    }

    const servicePath = `/etc/systemd/system/sslocal_${configName}.service`
    const serviceTemplate = fs.readFileSync('service_template.service', 'utf8')

    const serviceTemplateArray = serviceTemplate.split('\n')
    const serviceTemplateIndex = serviceTemplateArray.findIndex((line) =>
      line.includes('ExecStart')
    )
    serviceTemplateArray[
      serviceTemplateIndex
    ] = `ExecStart=/usr/local/bin/sslocal -c /etc/shadowsocks/config_${configName}.json`
    const newServiceTemplate = serviceTemplateArray.join('\n')
    fs.writeFileSync(servicePath, newServiceTemplate)
    //enable and start sslocal_$configName.service
    await exec(`systemctl daemon-reload`)
    await exec(`systemctl start sslocal_${configName}.service`)
    let retry = 0
    let maxRetry = 20
    for (retry = 0; retry < maxRetry; retry++) {
      try {
        //check socks5://localhost:socks5Port to fake.chiacloud.farm/ip using axios, if response.data == publicIp, break
        let socks5Url
        if (socks5User && socks5Pass) {
          socks5Url = `socks5://${socks5User}:${socks5Pass}@${hostPublicIp}:${socks5Port}`
        } else {
          socks5Url = `socks5://${hostPublicIp}:${socks5Port}`
        }
        const agent = new SocksProxyAgent(socks5Url)
        console.log(`try to connect using ${socks5Url}`)
        const response = await axios.request({
          url: 'http://fake.chiacloud.farm/ip',
          method: 'GET',
          httpsAgent: agent,
          httpAgent: agent,
          timeout: 1000,
        })
        if (response.data == publicIp) {
          break
        }
      } catch (err) {
        await sleep(1000)
        continue
      }
    }
    if (retry >= maxRetry) {
      throw new Error('retry proxy connection exceed maxRetry')
    }
    //remove configName from runningprocess.txt
    runningProcess = fs.readFileSync('runningprocess.txt', 'utf8')
    runningProcessArray = runningProcess.split('\n')
    runningProcessIndex = runningProcessArray.findIndex((line) =>
      line.includes(`${configName}|`)
    )
    runningProcessArray.splice(runningProcessIndex, 1)
    const newRunningProcess = runningProcessArray.join('\n')
    fs.writeFileSync('runningprocess.txt', newRunningProcess)
    let socks5Proxy
    if (socks5User && socks5Pass) {
      socks5Proxy = `${socks5User}:${socks5Pass}@${apiHostName}:${socks5Port}`
    } else {
      socks5Proxy = `${apiHostName}:${socks5Port}`
    }
    result.proxy = {
      socks5: socks5Proxy,
      http: `${apiHostName}:${httpPort}`,
      shadowsocks: `${host}:8388`,
    }
    result.configName = configName
    const endTime = performance.now()
    const executionTime = parseInt((endTime - startTime) / 1000) // convert to seconds
    return res.status(200).json({
      success: true,
      result: {
        configName: configName,
        oldIp: result.oldIp,
        newIp: result.newIp,
        proxy: result.proxy,
      },
      executionTime: `${executionTime} seconds`,
    })
  } catch (err) {
    console.error(err)
    //remove configName from runningprocess.txt
    runningProcess = fs.readFileSync('runningprocess.txt', 'utf8')
    runningProcessArray = runningProcess.split('\n')
    runningProcessIndex = runningProcessArray.findIndex(
      (line) => line == configName
    )
    runningProcessArray.splice(runningProcessIndex, 1)
    const newRunningProcess = runningProcessArray.join('\n')
    fs.writeFileSync('runningprocess.txt', newRunningProcess)
    const endTime = performance.now()
    const executionTime = parseInt((endTime - startTime) / 1000) // convert to seconds
    return res.status(500).json({
      success: false,
      configName: configName,
      error: err.message,
      executionTime: `${executionTime} seconds`,
    })
  }
})

app.get(`/${prefix}/checkConfig`, async (req, res) => {
  console.log('hit checkConfig')
  const { configs } = await parseConfig()
  const tencentConfigList = configs.tencent
  const cloudflareConfig = configs.cloudflare
  const awsConfigList = configs.aws
  const azureConfigList = configs.azure
  const civoConfigList = configs.civo
  let cloudflareCheckResult = {}
  let tencentCheckResult = []
  let awsCheckResult = []
  let azureCheckResult = []
  let civoCheckResult = []
  let result = {}

  try {
    cloudflareCheckResult = await checkCloudflare(cloudflareConfig)
    tencentCheckResult = await Promise.all(
      tencentConfigList.map((config) => checkTencent(config))
    )
    awsCheckResult = await Promise.all(
      awsConfigList.map((config) => checkAws(config))
    )
    azureCheckResult = await Promise.all(
      azureConfigList.map((config) => checkAzure(config))
    )
    civoCheckResult = await Promise.all(
      civoConfigList.map((config) => checkCivo(config))
    )
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message })
  }
  result.cloudflare = cloudflareCheckResult
  if (tencentCheckResult.length > 0) {
    result.tencent = tencentCheckResult
  }
  if (awsCheckResult.length > 0) {
    result.aws = awsCheckResult
  }
  if (azureCheckResult.length > 0) {
    result.azure = azureCheckResult
  }
  if (civoCheckResult.length > 0) {
    result.civo = civoCheckResult
  }

  return res.status(200).json({
    success: true,
    result: result,
  })
})

exports.parseConfig = parseConfig
exports.refreshCreds = refreshCreds
exports.checkCloudflare = checkCloudflare
