const express = require('express')
const router = express.Router()
const axios = require('axios')
const cheerio = require('cheerio')
const fs = require('fs')
const ConfigParser = require('configparser')
const config = new ConfigParser()
const { exec } = require('child_process')
config.read('config.conf')
const { performance } = require('perf_hooks')
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const { SocksProxyAgent } = require('socks-proxy-agent')
const fromMain = require('../index.js')

async function newIpCivo(serverConfig) {
  async function switchRegion(serverConfig) {
    const cookie = serverConfig.cookie
    const region = serverConfig.region
    if (!region) {
      throw new Error('Region not found')
    }
    const baseurl = `https://dashboard.civo.com/region/${region}?url=`
    const url = baseurl + encodeURIComponent('https://dashboard.civo.com/')
    const headers = {
      authority: 'dashboard.civo.com',
      accept:
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      'accept-language': 'en-US,en;q=0.9,id;q=0.8',
      'cache-control': 'max-age=0',
      'content-type': 'application/x-www-form-urlencoded',
      cookie: `_civo_session=${cookie}`,
      origin: 'https://dashboard.civo.com',
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
    }
    const result = await axios.get(url, { headers }).then((response) => {
      let result = {}
      const followUrl = response.request.res.responseUrl
      const body = response.data
      const token = body.match(/<meta name="csrf-token" content="(.*)" \/>/)[1]
      const cookie = response.headers['set-cookie'][0]
        .split(';')[0]
        .split('=')[1]
      result.token = token
      result.cookie = cookie
      return result
    })
    return result
  }

  async function getReservedIp(serverConfig) {
    const cookie = serverConfig.cookie
    const instanceId = serverConfig.instanceId
    const headers = {
      authority: 'dashboard.civo.com',
      accept:
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      'accept-language': 'en-US,en;q=0.9,id;q=0.8',
      'cache-control': 'max-age=0',
      cookie: `_civo_session=${cookie}`,
      referer: 'https://dashboard.civo.com',
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
    }

    try {
      const response = await axios.get(
        'https://dashboard.civo.com/reserved-ips',
        { headers }
      )
      const $ = cheerio.load(response.data)
      const listIp = []
      $('table tbody tr').each((i, el) => {
        const ipAddress = $(el).find('td').eq(0).text().trim()
        const ipName = $(el).find('td').eq(1).text().trim()
        const ipId = $(el)
          .find('td')
          .eq(1)
          .find('i')
          .attr('data-url')
          .split('/')[2]
          .trim()
        function checkAssigned(el) {
          const assign = $(el).find('td').eq(2).text().trim()
          if (assign === 'Not yet assigned') {
            return false
          } else {
            return true
          }
        }
        const assign = checkAssigned(el)
        const ip = {
          name: ipName,
          id: ipId,
          assigned: assign,
          address: ipAddress,
        }
        listIp.push(ip)
      })
      const reservedIp = listIp.find((el) => el.name === instanceId)
      return reservedIp
    } catch (error) {
      console.error(`error getting reserved ip`)
    }
  }

  function deleteReservedIp(serverConfig, reservedIpId) {
    const cookie = serverConfig.cookie
    const token = serverConfig.token
    axios
      .delete(`https://dashboard.civo.com/reserved-ips/${reservedIpId}`, {
        headers: {
          authority: 'dashboard.civo.com',
          accept: 'application/json, text/javascript, */*; q=0.01',
          'accept-language': 'en-US,en;q=0.9,id;q=0.8',
          'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
          cookie: `_civo_session=${cookie}`,
          origin: 'https://dashboard.civo.com',
          referer: 'https://dashboard.civo.com/reserved-ips',
          'sec-ch-ua':
            '"Google Chrome";v="113", "Chromium";v="113", "Not-A.Brand";v="24"',
          'sec-ch-ua-mobile': '?0',
          'sec-ch-ua-platform': '"Linux"',
          'sec-fetch-dest': 'empty',
          'sec-fetch-mode': 'cors',
          'sec-fetch-site': 'same-origin',
          'user-agent':
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
          'x-csrf-token': token,
          'x-requested-with': 'XMLHttpRequest',
        },
        data: '_method=delete',
      })
      .then((response) => {
        return
      })
      .catch((error) => {
        console.error(`error deleting reserved ip`)
      })
  }

  async function getPublicIp(cookie, instanceId) {
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
      result.success = true
      //parse ipaddress from this pattern <li>Public IP: <span class="js-clipboard" data-clipboard-text="74.220.18.67">74.220.18.67</span>
      try {
        ip = body.match(
          /<li>Public IP: <span class="js-clipboard" data-clipboard-text="(.*)">(.*)<\/span>/
        )[1]
      } catch (e) {
        ip = null
      }
      //parse text from this pattern <a class="underlined-link" href="/reserved-ips">Reserved IP</a>
      reserved = body.match(
        /<a class="underlined-link" href="\/reserved-ips">Reserved IP<\/a>/
      )
      if (reserved) {
        result.reserved = true
      } else {
        result.reserved = false
      }
      result.ip = ip
    } catch (error) {
      result.status = false
    }
    return result
  }

  async function assignReservedIp(instanceId, reservedIpId, token, cookie) {
    const config = {
      method: 'post',
      url: `https://dashboard.civo.com/instances/${instanceId}/assign_reserved_ip`,
      headers: {
        authority: 'dashboard.civo.com',
        accept: 'application/json, text/javascript, */*; q=0.01',
        'accept-language': 'en-US,en;q=0.9,id;q=0.8',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        cookie: `_civo_session=${cookie}`,
        origin: 'https://dashboard.civo.com',
        referer: `https://dashboard.civo.com/instances/${instanceId}`,
        'sec-ch-ua':
          '"Google Chrome";v="113", "Chromium";v="113", "Not-A.Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Linux"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent':
          'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'x-csrf-token': token,
        'x-requested-with': 'XMLHttpRequest',
      },
      data: {
        authenticity_token: token,
        reserved_ip_assign: reservedIpId,
      },
    }

    try {
      const response = await axios(config)
      return response.data
    } catch (error) {
      console.log('error assignReservedIp')
    }
  }

  async function releaseReservedIp(
    reservedIpId,
    reservedIpAddress,
    cookie,
    token
  ) {
    const result = {}
    const url = `https://dashboard.civo.com/reserved-ips/${reservedIpId}/release-ip`
    const headers = {
      authority: 'dashboard.civo.com',
      accept: 'application/json, text/javascript, */*; q=0.01',
      'accept-language': 'en-US,en;q=0.9,id;q=0.8',
      'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
      cookie: `_civo_session=${cookie}`,
      origin: 'https://dashboard.civo.com',
      referer:
        'https://dashboard.civo.com/instances/cc464313-e7a2-49be-8f0a-9e24ca97f9f2',
      'sec-ch-ua':
        '"Google Chrome";v="113", "Chromium";v="113", "Not-A.Brand";v="24"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Linux"',
      'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors',
      'sec-fetch-site': 'same-origin',
      'user-agent':
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
      'x-csrf-token': token,
      'x-requested-with': 'XMLHttpRequest',
    }
    const data = {
      authenticity_token: token,
      reserved_ip_address: reservedIpAddress,
    }

    try {
      const response = await axios.post(url, data, { headers })
      result.success = true
    } catch (error) {
      result.success = false
    }
  }

  async function createReservedIp(cookie, token, instanceId) {
    const url = 'https://dashboard.civo.com/reserved-ips'
    const headers = {
      authority: 'dashboard.civo.com',
      accept:
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      'accept-language': 'en-US,en;q=0.9,id;q=0.8',
      'cache-control': 'max-age=0',
      'content-type': 'application/x-www-form-urlencoded',
      cookie: `_civo_session=${cookie}`,
      origin: 'https://dashboard.civo.com',
      referer: 'https://dashboard.civo.com/reserved-ips/new',
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
    }

    const data = {
      authenticity_token: token,
      name: instanceId,
      commit: 'Create',
    }

    try {
      const response = await axios.post(url, data, { headers })
      return
    } catch (error) {
      console.error(error)
    }
  }

  async function assignPublicIp(instanceId, cookie) {
    const url = `https://dashboard.civo.com/instances/${instanceId}/assign_public_ip`
    const headers = {
      authority: 'dashboard.civo.com',
      accept:
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      'accept-language': 'en-US,en;q=0.9,id;q=0.8',
      cookie: `_civo_session=${cookie}`,
      referer: `https://dashboard.civo.com/instances/${instanceId}`,
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
    }

    try {
      const response = await axios.get(url, { headers })
    } catch (error) {
      return false
    }
    return true
  }

  const { cookie, token, instanceId } = serverConfig
  await switchRegion(serverConfig).catch((error) => {
    throw new Error(error)
  })

  const startTime = performance.now()
  const data = await getPublicIp(cookie, instanceId)
  const oldIp = data
  let assignNewIp
  let reservedIpId
  let reservedIpAddress
  let currentIp
  if (!data.ip) {
    while (!assignNewIp) {
      assignNewIp = await assignPublicIp(instanceId, cookie)
      sleep(500)
    }
  } else if (data.reserved !== true) {
    await createReservedIp(cookie, token, instanceId)
    sleep(1000)
    while (!reservedIpAddress && !reservedIpId) {
      const reservedIp = await getReservedIp(serverConfig)
      reservedIpAddress = reservedIp.address
      reservedIpId = reservedIp.id
    }
    await assignReservedIp(instanceId, reservedIpId, token, cookie)
    sleep(1000)
    currentIp = await getPublicIp(cookie, instanceId)
    while (currentIp.reserved === true) {
      const reservedIp = await getReservedIp(serverConfig)
      reservedIpAddress = reservedIp.address
      reservedIpId = reservedIp.id
      await releaseReservedIp(reservedIpId, reservedIpAddress, cookie, token)
      sleep(1000)
      currentIp = await getPublicIp(cookie, instanceId)
    }
    while (!assignNewIp) {
      assignNewIp = await assignPublicIp(instanceId, cookie)
      sleep(500)
    }
  } else if (data.reserved === true) {
    while (!reservedIpAddress && !reservedIpId) {
      const reservedIp = await getReservedIp(serverConfig)
      reservedIpAddress = reservedIp.address
      reservedIpId = reservedIp.id
    }
    sleep(1000)
    currentIp = await getPublicIp(cookie, instanceId)
    while (currentIp.reserved === true) {
      const reservedIp = await getReservedIp(serverConfig)
      reservedIpAddress = reservedIp.address
      reservedIpId = reservedIp.id
      await releaseReservedIp(reservedIpId, reservedIpAddress, cookie, token)
      sleep(1000)
      currentIp = await getPublicIp(cookie, instanceId)
    }
    while (!assignNewIp) {
      assignNewIp = await assignPublicIp(instanceId, cookie)
      sleep(500)
    }
  }
  const newIp = await getPublicIp(cookie, instanceId)
  if (reservedIpId && reservedIpAddress) {
    await deleteReservedIp(serverConfig, reservedIpId)
  }
  const endTime = performance.now()
  const time = parseInt((endTime - startTime) / 1000)
  const newIpAddress = newIp.ip
  const result = {
    oldIp: oldIp.ip,
    newIp: newIpAddress,
  }
  return result
}

router.get('/checkConfig', async function (req, res, next) {
  const { configs } = await fromMain.parseConfig()
  let civoCheckResult
  let cloudflareCheckResult
  try {
    const cloudflareConfig = configs.cloudflare
    cloudflareCheckResult = await checkCloudflare(cloudflareConfig)
    const civoConfigList = configs.civo
    civoCheckResult = await Promise.all(
      civoConfigList.map((config) => checkCivo(config))
    )
  } catch (error) {
    console.log(error)
  }
  return res.status(200).json({
    success: true,
    result: {
      cloudflare: cloudflareCheckResult,
      civo: civoCheckResult,
    },
  })
})

router.get('/newip', async function (req, res, next) {
  const startTime = performance.now()
  const configName = req.query.configName
  let result
  if (!configName) {
    res.status(400).send('configName is required')
  }
  console.log(`Hit newip endpoint with configName: ${configName}`)
  const { configs } = await fromMain.parseConfig()
  try {
    const apiConfig = configs.api
    const apiHostName = apiConfig.apiHostName
    const cloudflareConfig = configs.cloudflare
    const domain = cloudflareConfig.domain
    const email = cloudflareConfig.email
    let zoneId = cloudflareConfig.zoneId
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

    const civoConfigList = configs.civo
    const serverConfig = civoConfigList.find(
      (config) => config.configName === configName
    )
    if (!serverConfig) {
      return res
        .status(400)
        .json({ success: false, message: 'config not found' })
    }
    result = await newIpCivo(serverConfig)
    const socks5Port = serverConfig.socks5Port
    const httpPort = serverConfig.httpPort
    const publicIp = result.newIp
    const socks5User = serverConfig.socks5User
    const socks5Pass = serverConfig.socks5Pass
    if (result.oldIp === result.newIp || !result.newIp) {
      return res.status(400).json({
        success: false,
        configName: configName,
        message: 'fail to change Ip Address',
      })
    }
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

module.exports = router
