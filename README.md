# csa-attack
기존 beacon frame을 capture한 이후 tagged parameter에 5바이트의 Channel Switch Announcement 정보를 삽입하여 전송한다. New Channel Number는 실제 채널 값이 아닌 임의의 번호. 가급적 tag number가 정렬되도록 할 것.


흠.. 일단 브로드캐스트, 유니캐스트 둘다 끊기긴한다.

다만.
패킷을 보내는 반복문이 거의 끝나갈때쯤 되서야 끊기고, 길이가 계속 변한다
(ex. 278->285, 270->275, 280->285)

뭐때문일까..