SELECT
count (flow_id),
COUNT(case WHEN label_id!=1 THEN label_id END) as attacks
from traffic_flows