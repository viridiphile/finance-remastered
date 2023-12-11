var names = [];
var values = [];

document.addEventListener("DOMContentLoaded", function (event) {
  const totalPrice = document.querySelectorAll(".share-total");
  const shareName = document.querySelectorAll(".share-name");

  shareName.forEach((element) => {
    console.log(element.textContent);
    names.push(element.textContent)
  });

  totalPrice.forEach((element) => {
    console.log(element.textContent);
    values.push(element.textContent)
  });

  var layout = { title: "Shares vs. Value" };

  var data = [{ labels: names, values: values, type: "pie" }];

  Plotly.newPlot("myDiv", data, layout);
});
