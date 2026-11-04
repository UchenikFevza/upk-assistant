import os
import json
import logging
from dotenv import load_dotenv
import google.generativeai as genai
from google.api_core.exceptions import ResourceExhausted, GoogleAPIError

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AI_Service")

# Ключи читаются из переменной окружения (через запятую)
raw_keys = os.getenv("GEMINI_API_KEYS", "")
GEMINI_API_KEYS = [k.strip() for k in raw_keys.split(",") if k.strip()]

# Твой список рабочих моделей
AVAILABLE_MODELS = [
    "gemini-3.5-flash-lite",
    "gemini-flash-lite-latest",
    "gemini-3.1-flash-lite",
    "gemini-2.5-flash-lite",
    "gemini-flash-latest",
    "gemini-2.5-flash",
    "gemini-3.5-flash"
]

SYSTEM_PROMPT = """
Ты — вежливый цифровой ассистент колледжа.

ПРАВИЛА ОБЩЕНИЯ И ТОНАЛЬНОСТИ:
1. Соблюдай строгий деловой этикет, проявляй вежливость, уважение и сдержанность.
2. Обращайся к заявителю корректно («Здравствуйте», «Пожалуйста», «Благодарим за обращение»).

ФИЛЬТРАЦИЯ ТЕМАТИКИ (КРИТИЧЕСКИ ВАЖНО):
1. Система обрабатывает ТОЛЬКО вопросы, связанные с колледжем:
   - Всё что касается преподавателей или дату и время пар: сообщай, что у тебя нет доступа к персональным данным и расписанию занятий.
   - Аудитории, кабинеты, корпуса, коридоры, мебель, окна, двери, замки;
   - Электрика, освещение, розетки, выключатели, щитки;
   - Электронная и вычислительная техника колледжа (компьютеры, проекторы, интерактивные доски, принтеры, сеть Wi-Fi, кабели);
   - Чистота, порядок и санитарное состояние помещений.
2. ЕСЛИ ВОПРОС НЕ КАСАЕТСЯ КОЛЛЕДЖА ИЛИ ЕГО ТЕХНИКИ:
   - Установи "type": "off_topic" и "is_college_related": false.
   - В поле "ai_answer" вежливо, но настойчиво укажи, что данный сервис предназначен исключительно для вопросов функционирования инфраструктуры, помещений и оборудования колледжа.

ВЫЗОВ ПОДДЕРЖКИ / ЧЕЛОВЕКА:
- Если пользователь пишет «позови поддержку», «позовите оператора», «соедини с человеком», «нужна помощь сотрудника»:
  - Установи "type": "call_support", "should_create_ticket": true.
  - "ai_answer": "Здравствуйте! Переключаю обращение на ответственного сотрудника поддержки УПК. Ваша заявка передана специалисту."

ПРАВИЛА БЕЗОПАСНОСТИ:
- При любых признаках опасности (дым, искрение розеток, запах гари, оголенные провода): запрети самостоятельный ремонт, порекомендуй отойти и немедленно позвать дежурного. "type": "danger", "is_dangerous": true, "should_create_ticket": true.

ФОРМАТ ОТВЕТА — ТОЛЬКО ВАЛИДНЫЙ JSON:
{
  "type": "info_question" | "incident" | "danger" | "need_clarification" | "call_support" | "off_topic",
  "is_college_related": true | false,
  "ai_answer": "Текст ответа пользователю",
  "should_create_ticket": true | false,
  "is_dangerous": true | false,
  "suggested_category": "Оборудование" | "Мебель" | "Электрика" | "Сантехника" | "Чистота" | "Прочее" | null,
  "suggested_title": "Краткий заголовок проблемы или null",
  "extracted_location": "Номер кабинета/место или null",
  "confidence": 0.0-1.0
}
"""

class GeminiRotator:
    def __init__(self, api_keys: list[str], models: list[str]):
        self.api_keys = [k.strip() for k in api_keys if k.strip()]
        self.models = models
        self.current_key_index = 0

    def _get_current_key(self) -> str:
        return self.api_keys[self.current_key_index]

    def _rotate_key(self):
        old_idx = self.current_key_index
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        logger.warning(f"Ротация ключа: переключение с #{old_idx} на #{self.current_key_index}")

    def generate(self, user_text: str) -> dict:
        if not self.api_keys:
            return self._fallback_error("API-ключи не настроены.")

        # Быстрый триггер оператора без траты токенов
        support_triggers = ["позови поддержку", "вызови поддержку", "позовите оператора", "нужен человек", "оператор"]
        if any(trigger in user_text.lower() for trigger in support_triggers):
            return {
                "type": "call_support",
                "is_college_related": True,
                "ai_answer": "Здравствуйте! Переключаю обращение на ответственного сотрудника поддержки УПК. Ваша заявка передана специалисту.",
                "should_create_ticket": True,
                "is_dangerous": False,
                "suggested_category": "Прочее",
                "suggested_title": "Вызов специалиста поддержки",
                "extracted_location": None,
                "confidence": 1.0
            }

        last_error = ""
        attempts = len(self.api_keys)

        while attempts > 0:
            current_key = self._get_current_key()
            try:
                genai.configure(api_key=current_key)
                
                model = genai.GenerativeModel(
                    model_name=self.models[0],
                    system_instruction=SYSTEM_PROMPT,
                    generation_config={"response_mime_type": "application/json", "temperature": 0.1}
                )

                response = model.generate_content(user_text)
                return json.loads(response.text)

            except ResourceExhausted as e:
                last_error = f"Лимит исчерпан: {e}"
                print(f"[Ключ #{self.current_key_index}] {last_error}")
                self._rotate_key()
                attempts -= 1
            except GoogleAPIError as e:
                last_error = f"Ошибка Google API: {e}"
                print(f"[Ключ #{self.current_key_index}] {last_error}")
                self._rotate_key()
                attempts -= 1
            except Exception as e:
                last_error = f"Сбой: {e}"
                print(f"[Ключ #{self.current_key_index}] {last_error}")
                self._rotate_key()
                attempts -= 1

        return self._fallback_error(f"Ошибка обращения к ИИ: {last_error}")

    def _fallback_error(self, message: str) -> dict:
        return {
            "type": "incident",
            "is_college_related": True,
            "ai_answer": f"Сервис временно переведен в ручной режим ({message}). Пожалуйста, оформите заявку стандартным способом.",
            "should_create_ticket": True,
            "is_dangerous": False,
            "suggested_category": "Прочее",
            "suggested_title": "Обращение заявителя",
            "extracted_location": None,
            "confidence": 0.0
        }

ai_service = GeminiRotator(GEMINI_API_KEYS, AVAILABLE_MODELS)

def analyze_user_request(text: str) -> dict:
    return ai_service.generate(text)