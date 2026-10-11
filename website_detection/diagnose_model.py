
from final_detector import model

print("Model type:", type(model))
print("Model classes:", model.classes_)

if hasattr(model, "named_steps"):
    print("Pipeline steps:", list(model.named_steps.keys()))

test_urls = [
    "https://google.com/",
    "https://wikipedia.org/",
    "https://chatgpt.com/",
    "https://github.com/",
]

for url in test_urls:
    probabilities = model.predict_proba([url])[0]
    print("\nURL:", url)

    for label, probability in zip(model.classes_, probabilities):
        print(
            f"Label {label}: {probability * 100:.2f}%"
        )

    print("Predicted label:", model.predict([url])[0])
