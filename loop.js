const axios = require('axios')
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const fromMain = require('./index.js')
const parseConfig = fromMain.parseConfig
const refreshCreds = fromMain.refreshCreds

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

      await refreshCreds(response, configName)

      if (ip) {
        result.success = true
        result.token = token
        result.cookie = cookie
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

;(async () => {
  const { configs } = await parseConfig()
  const civoConfigList = configs.civo
  //loop through civo config list with promise all
  const civoResult = await Promise.all(
    civoConfigList.map(async (civoConfig) => {
      const result = await checkCivo(civoConfig)
      if (result.success) {
        console.log(
          `Config Civo ${civoConfig.configName} refreshed running with ip ${result.ip}`
        )
      } else {
        console.log(
          `Config Civo ${civoConfig.configName} refreshed failed with message ${result.message}`
        )
        return result
      }
    })
  )
  sleep(300000)
})()
