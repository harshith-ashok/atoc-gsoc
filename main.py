import network
import time
import machine
import dht
import urequests

SSID = "echo_base"
PASSWORD = "ECHOECHO123"

HOST_URL = "http://192.168.0.84:8000/led"

LED_PIN = 2
DHT_PIN = 4

led = machine.Pin(LED_PIN, machine.Pin.OUT)
sensor = dht.DHT11(machine.Pin(DHT_PIN))


def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)

    if not wlan.isconnected():
        print("Connecting to Wi-Fi...")
        wlan.connect(SSID, PASSWORD)

        while not wlan.isconnected():
            time.sleep(1)

    print("\nConnected to Wi-Fi")
    print("IP Address:", wlan.ifconfig()[0])


def read_sensor():
    sensor.measure()
    return sensor.temperature(), sensor.humidity()


def poll_server():
    response = None

    try:
        response = urequests.get(HOST_URL)

        state = response.text.strip()
        response.close()

        if state == "ON":
            led.on()
        else:
            led.off()

        temp, hum = read_sensor()

        print("LED:", state)
        print("Temperature:", temp, "C")
        print("Humidity:", hum, "%")
        print("-------------------------")

    except Exception as e:
        print("Error:", e)
        if response:
            try:
                response.close()
            except:
                pass


def main():
    connect_wifi()

    while True:
        poll_server()
        time.sleep(5)


main()