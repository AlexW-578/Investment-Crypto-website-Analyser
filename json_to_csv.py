import pandas as pd


def main():

    df = pd.read_json("./datasets/done/trendmicro_websites.json")
    df1 = df.T
    df1.to_csv("./datasets/done/trendmicro_websites.csv")

    df = pd.read_csv("./datasets/done/all.csv")
    df = df.drop_duplicates()
    df.to_csv("./datasets/done/all.csv")


if __name__ == "__main__":
    main()
