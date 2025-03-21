from fastapi import FastAPI, File, UploadFile, HTTPException , Request
import uvicorn
import os
from elasticsearch import Elasticsearch
import uuid
import json
import requests
from fastapi.responses import JSONResponse
from typing import List
from fastapi.middleware.cors import CORSMiddleware
import traceback

# FastAPI uygulamasını oluştur
app = FastAPI()

app.add_middleware(CORSMiddleware,
                   allow_origins=["*"],
                   allow_credentials=True,
                   allow_methods=["*"],
                   allow_headers=["*"]
                   )

# Elasticsearch bağlantısı
ELASTICSEARCH_URL = "http://localhost:9200"
es = Elasticsearch([ELASTICSEARCH_URL])

# Log dosyalarının yükleneceği dizin
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


def convert_data_types(doc: dict) -> dict:
    """
    IIS log formatındaki alanları Elasticsearch için düzeltilmiş adlarla eşler.
    Verileri uygun türlerde dönüştürür.
    """
    field_mapping = {
        "c-ip": "c_ip", "s-ip": "s_ip", "s-port": "s_port", "sc-status": "sc_status",
        "sc-substatus": "sc_substatus", "sc-win32-status": "sc_win32_status", "time-taken": "time_taken",
        "cs-method": "cs_method", "cs-uri-stem": "cs_uri_stem", "cs-uri-query": "cs_uri_query",
        "cs-username": "cs_username", "cs(Referer)": "cs_referer", "cs(User-Agent)": "cs_user_agent",
        "x-forwarded-for": "x_forwarded_for", "date": "date", "time": "time"
    }

    converted_doc = {}

    for key, value in doc.items():
        new_key = field_mapping.get(key, key)

        if value in ["", "-"]:
            converted_doc[new_key] = None
            continue
        
        # Sayısal değerler için dönüşüm
        if new_key in ["s_port", "sc_status", "sc_substatus", "sc_win32_status", "time_taken"]:
            try:
                converted_doc[new_key] = int(value)
            except ValueError:
                converted_doc[new_key] = None
        
        # IP adreslerini string olarak bırak
        elif new_key in ["s_ip", "c_ip", "x_forwarded_for"]:
            converted_doc[new_key] = str(value)
        
        # Diğer metin alanlarını string olarak bırak
        elif new_key in ["cs_uri_query", "cs_user_agent", "cs_referer", "cs_method", "cs_uri_stem", "cs_username"]:
            converted_doc[new_key] = str(value)
        
        # Tarih ve saat alanlarını string olarak bırak
        elif new_key in ["date", "time"]:
            converted_doc[new_key] = value
        
        else:
            converted_doc[new_key] = value  # Varsayılan olarak olduğu gibi bırak
    
    return converted_doc


@app.get("/")
async def root():
    return {"message": "FastAPI Çalışıyor!"}

async def upload_log(uploaded_file: UploadFile = File(...)):
    """
    Log dosyasını yükler.
    """
    try:
        file_location = os.path.join(UPLOAD_DIR, uploaded_file.filename)
        with open(file_location, "wb") as f:
            f.write(await uploaded_file.read())
        
        return {"filename": uploaded_file.filename, "message": "File uploaded successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/test/")
async def test_api(text: str):
    return JSONResponse({"message": text})


@app.post("/parse_file/")
async def parse_log_file(uploaded_file: UploadFile = File(...)):
    """
    Yüklenen log dosyasını analiz eder ve verileri çıkarır.
    """
    upload_log(uploaded_file)
    try:
        if not uploaded_file.filename.endswith(".log"):
            raise HTTPException(status_code=400, detail="Sadece .log dosyaları desteklenmektedir.")

        content = await uploaded_file.read()
        print(content)

        try:
            lines = content.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            lines = content.decode("utf-16").splitlines()
            traceback.print_exc()

        # Başlık bilgilerini al
        software_type = lines[0].strip("#Software: ").split("\n")[0]
        version = lines[1].strip("#Version: ").split("\n")[0]
        created_date, created_time = lines[2].strip("#Date: ").split()

        # Sütun başlıklarını oku
        table_columns = lines[3].strip().split()[1:]

        # Satırları ayrıştır ve veri dönüşümünü uygula
        rows = [convert_data_types(dict(zip(table_columns, line.strip().split()))) for line in lines[4:]]

        return {
            "software_type": software_type,
            "version": version,
            "created_date": created_date,
            "created_time": created_time,
            "file_name": uploaded_file.filename,
            "dataframe": rows
        }

    except Exception as e:
        traceback.print_exc()

@app.post("/save_file_index_pair/")
async def save_file_index(file_name: str, index_name: str):
    """
    Dosya adını ve index adını Elasticsearch'e kaydeder.
    """
    try:
        doc = {
            "file_name": file_name,
            "index_name": index_name
        }
        es.index(index="file_index_mapping", document=doc)
        return {"message": "Dosya ve index adları başarıyla kaydedildi."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/get_file_index_pair/")
async def get_indexes_by_filename(file_name: str):
    """
    Yüklenen dosya adına karşılık gelen index adlarını listeler.
    """
    try:
        query = {
            "query": {
                "match": {
                    "file_name": file_name
                }
            }
        }
        res = es.search(index="file_index_mapping", body=query)
        indexes = [hit["_source"]["index_name"] for hit in res["hits"]["hits"]]
        return {"indexes": indexes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/get_all_file_index_pairs/")
async def get_all_file_index_pairs():
    """
    Tüm dosya-index eşleşmelerini listeler.
    """
    try:
        query = {
            "query": {
                "match_all": {}  # Tüm kayıtları getir
            }
        }
        res = es.search(index="file_index_mapping", body=query, size=10000)  # Büyük sonuçlar için size parametresi
        pairs = [{"file_name": hit["_source"]["file_name"], "index_name": hit["_source"]["index_name"]} for hit in res["hits"]["hits"]]
        return {"file_index_pairs": pairs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/save_to_es/")
async def save_to_es(data: dict):
    """
    Parse edilen veriyi Elasticsearch'e kaydeder.
    """
    try:
        created_date = data.get("created_date", "").replace("-", "")
        created_time = data.get("created_time", "").replace(":", "")
        unique_id = str(uuid.uuid4())[:8]
        index_name = f"iislogs_{created_date}_{created_time}_{unique_id}"

        for doc in data["dataframe"]:
            formatted_doc = convert_data_types(doc)
            es.index(index=index_name, document=formatted_doc)

        await save_file_index(file_name=data["file_name"], index_name=index_name)
        return {"message": f"Veri Elasticsearch'e başarıyla kaydedildi.", "index_name": index_name, "file_name": data["file_name"]}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.delete("/delete_file/{file_name}")
async def delete_file(file_name: str):
    """
    Yüklenen dosyayı ve ilgili index'i siler.
    """
    try:
        # Dosya adına karşılık gelen index adlarını al
        query = {
            "query": {
                "match": {
                    "file_name": file_name
                }
            }
        }
        res = es.search(index="file_index_mapping", body=query)
        hits = res["hits"]["hits"]

        if not hits:
            return {"message": f"{file_name} için index bulunamadı."}

        index_names = [hit["_source"]["index_name"] for hit in hits]

        # Index'leri sil
        for index_name in index_names:
            es.indices.delete(index=index_name, ignore=[400, 404])

        # Dosyayı sil
        file_location = os.path.join(UPLOAD_DIR, file_name)
        if os.path.exists(file_location):
            os.remove(file_location)

        # file_index_mapping'den kaydı sil
        for hit in hits:
            es.delete(index="file_index_mapping", id=hit["_id"])

        return {"message": f"{file_name} ve ilgili index'ler başarıyla silindi."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/get_endpoint_stats/")
async def get_kpi(index_name: str, endpoint: str):
    elastic_query = {
        "size": 0,
        "query": {
            "term": {
                "cs_uri_stem.keyword": endpoint
            }
        },
        "aggs": {
            "http_methods": {
                "terms": {
                    "field": "cs_method.keyword",
                    "size": 2
                }
            },
            "unique_users": {
                "cardinality": {
                    "field": "cs_username.keyword"
                }
            },
            "status_codes": {
                "terms": {
                    "field": "sc_status",
                    "size": 2
                }
            },
            "time_taken_stats": {
                "extended_stats": {
                    "field": "time_taken"
                }
            },
            "top_date": {
                "terms": {
                    "field": "date",
                    "size": 1,
                    "order": { "_count": "desc" }
                },
                "aggs": {
                    "date_time_taken_stats": {
                        "extended_stats": {
                            "field": "time_taken"
                        }
                    },
                    "date_status_codes": {
                        "terms": {
                            "field": "sc_status"
                        }
                    }
                }
            },
            "time_taken_max_details": {
                "top_hits": {
                    "sort": [
                        { "time_taken": { "order": "desc" } }
                    ],
                    "_source": {
                        "includes": ["date", "time", "time_taken", "sc_status", "c_ip"]
                    },
                    "size": 1
                }
            },
            "most_frequent_ip": {
                "terms": {
                    "field": "c_ip.keyword",
                    "size": 1
                }
            },
            "consecutive_500s": {
                "filter": {
                    "term": { "sc_status": 500 }
                },
                "aggs": {
                    "consecutive_500_times": {
                        "date_histogram": {
                            "field": "date",
                            "fixed_interval": "1d",
                            "min_doc_count": 1
                        }
                    }
                }
            }
        }
    }

    # Elasticsearch'a isteği gönder
    json_query = json.dumps(elastic_query)
    elastic_respond = requests.get(
        f"{ELASTICSEARCH_URL}/{index_name}/_search?pretty", 
        headers={"Content-Type": "application/json"}, 
        data=json_query
    )

    # Elasticsearch cevabını işleyip JSON formatında döndür
    response_data = elastic_respond.json()

    # KPI verilerini çıkartalım
    data = {
        "GET_count": next((bucket["doc_count"] for bucket in response_data["aggregations"]["http_methods"]["buckets"] if bucket["key"] == "GET"), 0),
        "POST_count": next((bucket["doc_count"] for bucket in response_data["aggregations"]["http_methods"]["buckets"] if bucket["key"] == "POST"), 0),
        "unique_users_count": response_data["aggregations"]["unique_users"]["value"],
        "status_codes_500_count": next((bucket["doc_count"] for bucket in response_data["aggregations"]["status_codes"]["buckets"] if bucket["key"] == 500), 0),
        "status_codes_200_count": next((bucket["doc_count"] for bucket in response_data["aggregations"]["status_codes"]["buckets"] if bucket["key"] == 200), 0),
        "min_time_taken": response_data["aggregations"]["time_taken_stats"]["min"],
        "max_time_taken": response_data["aggregations"]["time_taken_stats"]["max"],
        "avg_time_taken": response_data["aggregations"]["time_taken_stats"]["avg"],
        "std_dev_time_taken": response_data["aggregations"]["time_taken_stats"]["std_deviation"],
        "total_requests_count": response_data["aggregations"]["time_taken_stats"]["count"],
        "most_requested_date": response_data["aggregations"]["top_date"]["buckets"][0]["key_as_string"],
        "max_time_taken_on_most_requested_date": response_data["aggregations"]["top_date"]["buckets"][0]["date_time_taken_stats"]["max"],
        "min_time_taken_on_most_requested_date": response_data["aggregations"]["top_date"]["buckets"][0]["date_time_taken_stats"]["min"],
        "avg_time_taken_on_most_requested_date": response_data["aggregations"]["top_date"]["buckets"][0]["date_time_taken_stats"]["avg"],
        "std_dev_time_taken_on_most_requested_date": response_data["aggregations"]["top_date"]["buckets"][0]["date_time_taken_stats"]["std_deviation"],
        "status_codes_500_on_most_requested_date": next((bucket["doc_count"] for bucket in response_data["aggregations"]["top_date"]["buckets"][0]["date_status_codes"]["buckets"] if bucket["key"] == 500), 0),
        "status_codes_200_on_most_requested_date": next((bucket["doc_count"] for bucket in response_data["aggregations"]["top_date"]["buckets"][0]["date_status_codes"]["buckets"] if bucket["key"] == 200), 0),
        "max_time_taken_request_date": response_data["aggregations"]["time_taken_max_details"]["hits"]["hits"][0]["_source"]["date"],
        "max_time_taken_request_time": response_data["aggregations"]["time_taken_max_details"]["hits"]["hits"][0]["_source"]["time"],
        "max_time_taken_request_status": response_data["aggregations"]["time_taken_max_details"]["hits"]["hits"][0]["_source"]["sc_status"],
        "most_frequent_ip": response_data["aggregations"]["most_frequent_ip"]["buckets"][0]["key"],
        "consecutive_500s_count": response_data["aggregations"]["consecutive_500s"]["doc_count"],
        "consecutive_500s_dates": [bucket["key_as_string"] for bucket in response_data["aggregations"]["consecutive_500s"]["consecutive_500_times"]["buckets"]]
    }

    # JSON olarak döndürüyoruz
    return JSONResponse(content=data)

@app.get("/list_endpoints/")
async def list_endpoints_from_indices(index_name:str):
    try:
        query={
        "size": 0,
        "aggs": {
            "unique_services": {
                "terms": {
                    "field": "cs_uri_stem.keyword",
                    "size": 10000
                    }
                }
            }
        }
        response_data=json.dumps(query)
        response=requests.get(f"{ELASTICSEARCH_URL}/{index_name}/_search", headers={"Content-Type": "application/json"},data=response_data)
        response_json=response.json()
        endpoints=[endpoint["key"] for endpoint in response_json["aggregations"]["unique_services"]["buckets"]]
        return endpoints
    except Exception as e :
        raise HTTPException(status_code=500,detail=str(e))
    

@app.get("/get_time_based_stats/")
async def get_time_based_stats_by_endpoint(index_name: str, endpoint: str):
    try:
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        { "term": { "cs_uri_stem.keyword": endpoint } }
                    ],
                    "filter": {
                        "range": {
                            "date": {
                                "gte": "1970-01-01", 
                                "lte": "now/d"
                            }
                        }
                    }
                }
            },
            "aggs": {
                "zaman_serisi": {
                    "date_histogram": {
                        "field": "date",
                        "calendar_interval": "1d",
                        "format": "yyyy-MM-dd"
                    },
                    "aggs": {
                        "durum_500": {
                            "filter": { "term": { "sc_status": 500 } }
                        },
                        "durum_200": {
                            "filter": { "term": { "sc_status": 200 } }
                        },
                        "min_time_taken": { "min": { "field": "time_taken" } },
                        "max_time_taken": { "max": { "field": "time_taken" } },
                        "ortalama_time_taken": { "avg": { "field": "time_taken" } }
                    }
                }
            }
        }

        query_json = json.dumps(query)
        response = requests.get(url=f'{ELASTICSEARCH_URL}/{index_name}/_search',
                                headers={"Content-Type": "application/json"},
                                data=query_json)
        
        # Parse response JSON to extract values
        data = response.json()
        
        if "aggregations" in data:
            # Iterate over all buckets to get results for each date
            result = []
            for bucket in data["aggregations"]["zaman_serisi"]["buckets"]:
                date = bucket["key_as_string"]
                durum_500_count = bucket["durum_500"]["doc_count"]
                durum_200_count = bucket["durum_200"]["doc_count"]
                ortalama_time_taken = bucket["ortalama_time_taken"]["value"]
                max_time_taken = bucket["max_time_taken"]["value"]
                min_time_taken = bucket["min_time_taken"]["value"]

                result.append({
                    "date": date,
                    "durum_500_count": durum_500_count,
                    "durum_200_count": durum_200_count,
                    "ortalama_time_taken": ortalama_time_taken,
                    "max_time_taken": max_time_taken,
                    "min_time_taken": min_time_taken
                })
            
            return JSONResponse(content=result)
        
        return JSONResponse(content={"message": "No data found for the given query."})
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/get_general_stats/")
async def get_general_stats(index_name: str):
    elastic_queries = {
        "error_rate_top_10": {
            "size": 0,
            "aggs": {
                "endpoints": {
                    "terms": {
                        "field": "cs_uri_stem.keyword",
                        "size": 10
                    },
                    "aggs": {
                        "total_requests": {
                            "value_count": {
                                "field": "cs_uri_stem.keyword"
                            }
                        },
                        "error_requests": {
                            "filter": {
                                "bool": {
                                    "should": [
                                        {
                                            "range": {
                                                "sc_status": {
                                                    "gte": 400
                                                }
                                            }
                                        },
                                        {
                                            "range": {
                                                "sc_status": {
                                                    "gte": 500
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            }
        },
        "response_time_top_20": {
            "size": 0,
            "aggs": {
                "endpoints": {
                    "terms": {
                        "field": "cs_uri_stem.keyword",
                        "size": 20,
                        "order": {
                            "avg_response_time": "desc"
                        }
                    },
                    "aggs": {
                        "avg_response_time": {
                            "avg": {
                                "field": "time_taken"
                            }
                        }
                    }
                }
            }
        },
        "most_requested_top_10": {
            "size": 0,
            "aggs": {
                "endpoints": {
                    "terms": {
                        "field": "cs_uri_stem.keyword",
                        "size": 10,
                        "order": {
                            "_count": "desc"
                        }
                    }
                }
            }
        },
        "error_client_ips_top_5": {
            "size": 0,
            "query": {
                "bool": {
                    "should": [
                        {
                            "range": {
                                "sc_status": {
                                    "gte": 400
                                }
                            }
                        },
                        {
                            "range": {
                                "sc_status": {
                                    "gte": 500
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "client_ips": {
                    "terms": {
                        "field": "c_ip.keyword",
                        "size": 5,
                        "order": {
                            "_count": "desc"
                        }
                    }
                }
            }
        },
        "response_time_client_ips_top_5": {
            "size": 0,
            "aggs": {
                "client_ips": {
                    "terms": {
                        "field": "c_ip.keyword",
                        "size": 5,
                        "order": {
                            "avg_response_time": "desc"
                        }
                    },
                    "aggs": {
                        "avg_response_time": {
                            "avg": {
                                "field": "time_taken"
                            }
                        }
                    }
                }
            }
        },
        "user_agents_top_10": {
            "size": 0,
            "aggs": {
                "user_agents": {
                    "terms": {
                        "field": "cs_user_agent.keyword",
                        "size": 10
                    }
                }
            }
        },
        "http_methods": {
            "size": 0,
            "aggs": {
                "http_methods": {
                    "terms": {
                        "field": "cs_method.keyword"
                    }
                }
            }
        },
        "error_rate_over_time": {
            "size": 0,
            "aggs": {
                "error_rate_over_time": {
                    "date_histogram": {
                        "field": "date",
                        "calendar_interval": "1d"
                    },
                    "aggs": {
                        "total_requests": {
                            "value_count": {
                                "field": "cs_uri_stem.keyword"
                            }
                        },
                        "error_requests": {
                            "filter": {
                                "bool": {
                                    "should": [
                                        {
                                            "range": {
                                                "sc_status": {
                                                    "gte": 400
                                                }
                                            }
                                        },
                                        {
                                            "range": {
                                                "sc_status": {
                                                    "gte": 500
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            }
        },
        "response_time_distribution": {
            "size": 0,
            "aggs": {
                "endpoints": {
                    "terms": {
                        "field": "cs_uri_stem.keyword",
                        "size": 10
                    },
                    "aggs": {
                        "response_time_stats": {
                            "stats": {
                                "field": "time_taken"
                            }
                        }
                    }
                }
            }
        }
    }

    results = {}
    for key, query in elastic_queries.items():
        json_query = json.dumps(query)
        elastic_respond = requests.get(
            f"{ELASTICSEARCH_URL}/{index_name}/_search?pretty",
            headers={"Content-Type": "application/json"},
            data=json_query
        )
        results[key] = elastic_respond.json()["aggregations"]

    return JSONResponse(content=results)


if __name__ == "__final__":
    uvicorn.run(port=8000)
