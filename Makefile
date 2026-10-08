
venv:
	uv sync

start-yamcs:
	docker compose up -d

stop-yamcs:
	docker compose down

restart-yamcs: stop-yamcs start-yamcs

watch-for-rx-drops:
	./watch-for-rx-drops.sh

watch-socket-buf-fill-levels:
	uv run ./watch-socket-buf-fill.py -i 0.25 udp:9900 udp:9901 udp:9902 udp:9903 udp:9904 udp:9905 udp:9906 udp:9907 --nice 20

stress-1:
	sudo .venv/bin/python3 ./stressor.py --pkt-rate-hz 1 --num-stressors 1

stress-100:
	sudo .venv/bin/python3 ./stressor.py --pkt-rate-hz 100 --num-stressors 1

stress-1000:
	sudo .venv/bin/python3 ./stressor.py --pkt-rate-hz 1000 --num-stressors 1

stress-2000:
	sudo .venv/bin/python3 ./stressor.py --pkt-rate-hz 1000 --num-stressors 2

stress-3000:
	sudo .venv/bin/python3 ./stressor.py --pkt-rate-hz 1000 --num-stressors 3

stress-4000:
	sudo .venv/bin/python3 ./stressor.py --pkt-rate-hz 1000 --num-stressors 4

stress-5000:
	sudo .venv/bin/python3 ./stressor.py --pkt-rate-hz 1000 --num-stressors 5

stress-6000:
	sudo .venv/bin/python3 ./stressor.py --pkt-rate-hz 1000 --num-stressors 6

stress-7000:
	sudo .venv/bin/python3 ./stressor.py --pkt-rate-hz 1000 --num-stressors 7

stress-8000:
	sudo .venv/bin/python3 ./stressor.py --pkt-rate-hz 1000 --num-stressors 8

stress-16000:
	sudo .venv/bin/python3 ./stressor.py --pkt-rate-hz 2000 --num-stressors 8