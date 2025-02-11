import hydra

from csp_gateway.server.config import run


@hydra.main(config_path="config", config_name="base", version_base=None)
def main(cfg):
    run(cfg)


if __name__ == "__main__":
    main()
